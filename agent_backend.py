import os
import sys
import json
import time
import asyncio
import threading
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("SecuritySentinelBackend")

# Globals for thread-safe asynchronous MCP connection
mcp_session = None
mcp_loop = None
mcp_thread = None
mcp_connected_event = threading.Event()

# ------------------------------------------------------------------------------
# Asynchronous Background MCP Client Lifecycle
# ------------------------------------------------------------------------------

async def mcp_client_lifecycle():
    global mcp_session, mcp_loop
    mcp_loop = asyncio.get_running_loop()
    
    # Locate server.py absolute path in workspace
    cwd = os.path.dirname(os.path.abspath(__file__))
    server_path = os.path.join(cwd, "server.py")
    
    # Use the same python executable running this backend to guarantee virtual env preservation
    python_exe = sys.executable
    logger.info(f"Spawning MCP Server subprocess: '{python_exe} {server_path}'")
    
    server_params = StdioServerParameters(
        command=python_exe,
        args=[server_path],
        env=os.environ.copy()
    )
    
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                logger.info("Initializing MCP protocol handshake...")
                await session.initialize()
                mcp_session = session
                logger.info("MCP Client connection initialized successfully!")
                
                # Signal main thread that we are connected
                mcp_connected_event.set()
                
                # Keep loop running indefinitely to process coroutines
                while True:
                    await asyncio.sleep(1)
    except Exception as e:
        logger.error(f"Fatal error in background MCP client loop: {e}")
        mcp_connected_event.set() # Avoid blocking forever on failure

def start_mcp_client_thread():
    global mcp_thread
    def run_loop():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(mcp_client_lifecycle())
        
    mcp_thread = threading.Thread(target=run_loop, daemon=True)
    mcp_thread.start()

# ------------------------------------------------------------------------------
# Synchronous Thread-Safe REST wrappers calling Async MCP functions
# ------------------------------------------------------------------------------

def call_mcp_read_resource(uri: str) -> str:
    """Invokes async session.read_resource thread-safely from HTTP main thread."""
    if not mcp_session:
        return json.dumps({"error": "MCP Client Session is not connected"})
        
    async def task():
        result = await mcp_session.read_resource(uri)
        return result.contents[0].text

    future = asyncio.run_coroutine_threadsafe(task(), mcp_loop)
    try:
        return future.result(timeout=10)
    except Exception as e:
        logger.error(f"Error calling MCP read_resource: {e}")
        return json.dumps({"error": str(e)})

def call_mcp_tool(name: str, arguments: dict) -> str:
    """Invokes async session.call_tool thread-safely from HTTP main thread."""
    if not mcp_session:
        return json.dumps({"error": "MCP Client Session is not connected"})
        
    async def task():
        result = await mcp_session.call_tool(name, arguments)
        return result.content[0].text

    future = asyncio.run_coroutine_threadsafe(task(), mcp_loop)
    try:
        return future.result(timeout=15)
    except Exception as e:
        logger.error(f"Error calling MCP tool '{name}': {e}")
        return json.dumps({"error": str(e)})

# ------------------------------------------------------------------------------
# HTTP Request Handler for Static Assets and API Endpoints
# ------------------------------------------------------------------------------

class SecuritySentinelHTTPHandler(BaseHTTPRequestHandler):
    
    def log_message(self, format, *args):
        # Redirect standard HTTP logging to our configured logger
        logger.debug(format % args)

    def do_GET(self):
        # 1. API Endpoints
        if self.path == "/api/governance":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response_content = call_mcp_read_resource("config://governance/autonomy-matrix")
            self.wfile.write(response_content.encode("utf-8"))
            return
            
        elif self.path == "/api/telemetry":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            
            # Fetch all default ETM assets telemetry logs and merge them
            assets = ["app-server-01", "db-host-05", "dev-box-09"]
            merged_telemetry = {}
            for asset_id in assets:
                try:
                    content_raw = call_mcp_read_resource(f"telemetry://active-session-logs/{asset_id}")
                    merged_telemetry[asset_id] = json.loads(content_raw)
                except Exception as e:
                    logger.error(f"Error fetching telemetry for {asset_id}: {e}")
                    
            self.wfile.write(json.dumps(merged_telemetry, indent=2).encode("utf-8"))
            return

        # 2. Static Asset Routing
        cwd = os.path.dirname(os.path.abspath(__file__))
        static_dir = os.path.join(cwd, "static")
        
        # Default route to index.html
        req_path = self.path
        if req_path == "/" or req_path == "":
            req_path = "/index.html"
            
        # Clean query parameters
        req_path = req_path.split("?")[0]
        file_path = os.path.abspath(os.path.join(static_dir, req_path.lstrip("/")))
        
        # Verify directory traversal security
        if not file_path.startswith(static_dir) or not os.path.exists(file_path) or os.path.isdir(file_path):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            return
            
        # Determine MIME Type
        mime_type = "text/html"
        if file_path.endswith(".css"):
            mime_type = "text/css"
        elif file_path.endswith(".js"):
            mime_type = "application/javascript"
        elif file_path.endswith(".png"):
            mime_type = "image/png"
            
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            logger.error(f"Error serving file {file_path}: {e}")
            self.send_response(500)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")
        
        try:
            body = json.loads(post_data) if post_data else {}
        except Exception:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON body")
            return

        if self.path == "/api/validate":
            asset_id = body.get("asset_id")
            cve_id = body.get("cve_id")
            
            if not asset_id or not cve_id:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing asset_id or cve_id parameters")
                return
                
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            
            # Execute TruConfirm exploit validation tool
            result = call_mcp_tool("delegate_validation_workflow", {"asset_id": asset_id, "cve_id": cve_id})
            self.wfile.write(result.encode("utf-8"))
            return
            
        elif self.path == "/api/remediate":
            asset_id = body.get("asset_id")
            action_type = body.get("action_type")
            change_control_id = body.get("change_control_id", "CC-9942")
            
            if not asset_id or not action_type:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing asset_id or action_type parameters")
                return
                
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            
            # Execute TruRisk Eliminate remediation tool
            result = call_mcp_tool("orchestrate_remediation", {
                "asset_id": asset_id,
                "action_type": action_type,
                "change_control_id": change_control_id
            })
            self.wfile.write(result.encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

# ------------------------------------------------------------------------------
# Orchestrator Main Entrypoint
# ------------------------------------------------------------------------------

def main():
    logger.info("Initializing Security Sentinel Orchestration Backend...")
    
    # 1. Start the MCP client stdio background thread
    start_mcp_client_thread()
    
    logger.info("Awaiting connection to local Agent Val MCP Server process...")
    # Block for max 10 seconds waiting for connection
    connected = mcp_connected_event.wait(timeout=10)
    
    if not connected or not mcp_session:
        logger.error("FATAL: Failed to connect to Agent Val MCP Server. Shutting down.")
        sys.exit(1)
        
    # 2. Boot HTTP Web GUI server
    server_address = ("", 8000)
    httpd = ThreadingHTTPServer(server_address, SecuritySentinelHTTPHandler)
    logger.info("======================================================================")
    logger.info("SECURITY SENTINEL WEB GUI PORTAL NOW ONLINE!")
    logger.info("Access the interactive dashboard in your browser:")
    logger.info("👉 http://localhost:8000 👈")
    logger.info("======================================================================")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down Security Sentinel Portal.")
    finally:
        httpd.server_close()
        logger.info("Portal HTTP server offline.")

if __name__ == "__main__":
    main()
