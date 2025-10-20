# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content

    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

@mcp.tool()
def read_memory(address: str, length: int = 16, format: str = "both") -> str:
    """
    Read memory from a specified address.

    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        length: Number of bytes to read (default: 16)
        format: Output format - "hex", "ascii", or "both" (default: "both")

    Returns:
        Memory contents in the specified format
    """
    return "\n".join(safe_get("read_memory", {"address": address, "length": length, "format": format}))

@mcp.tool()
def write_memory(address: str, data: str) -> str:
    """
    Write memory to a specified address.

    Args:
        address: Target address in hex format
        data: Hex string to write (e.g. "01020304")

    Returns:
        Success or error message
    """
    return safe_post("write_memory", {"address": address, "data": data})

@mcp.tool()
def get_program_info() -> str:
    """
    Get comprehensive information about the loaded program.

    Returns:
        Program metadata including name, architecture, compiler, memory layout, etc.
    """
    return "\n".join(safe_get("program_info"))

@mcp.tool()
def create_bookmark(address: str, category: str = "Analysis", comment: str = "") -> str:
    """
    Create a bookmark at the specified address.

    Args:
        address: Target address in hex format
        category: Bookmark category (default: "Analysis")
        comment: Optional comment for the bookmark

    Returns:
        Success or error message
    """
    return safe_post("create_bookmark", {"address": address, "category": category, "comment": comment})

@mcp.tool()
def list_bookmarks(offset: int = 0, limit: int = 100) -> list:
    """
    List all bookmarks in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of bookmarks to return (default: 100)

    Returns:
        List of bookmarks with their addresses, categories, and comments
    """
    return safe_get("list_bookmarks", {"offset": offset, "limit": limit})

@mcp.tool()
def create_label(address: str, name: str, primary: bool = True) -> str:
    """
    Create a label at the specified address.

    Args:
        address: Target address in hex format
        name: Label name
        primary: Whether this should be the primary symbol (default: True)

    Returns:
        Success or error message
    """
    return safe_post("create_label", {"address": address, "name": name, "primary": str(primary).lower()})

@mcp.tool()
def create_function(address: str, name: str = None) -> str:
    """
    Create a function at the specified address.

    Args:
        address: Function entry point address in hex format
        name: Optional function name (default: auto-generated)

    Returns:
        Success message with function details or error
    """
    data = {"address": address}
    if name:
        data["name"] = name
    return safe_post("create_function", data)

@mcp.tool()
def delete_function(address: str) -> str:
    """
    Delete a function at the specified address.

    Args:
        address: Function address in hex format

    Returns:
        Success or error message
    """
    return safe_post("delete_function", {"address": address})

@mcp.tool()
def list_data_types(offset: int = 0, limit: int = 100, filter: str = None) -> list:
    """
    List all data types available in the program.

    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of types to return (default: 100)
        filter: Optional filter to match type names

    Returns:
        List of data types with their sizes
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("list_data_types", params)

@mcp.tool()
def apply_data_type(address: str, data_type: str) -> str:
    """
    Apply a data type at the specified address.

    Args:
        address: Target address in hex format
        data_type: Name of the data type to apply

    Returns:
        Success message with applied type details or error
    """
    return safe_post("apply_data_type", {"address": address, "data_type": data_type})

@mcp.tool()
def create_structure(name: str, fields: str = None) -> str:
    """
    Create a new structure data type.

    Args:
        name: Structure name
        fields: Comma-separated field definitions in format "fieldName:typeName,..."
                Example: "x:int,y:int,name:char[20]"

    Returns:
        Success message with structure details or error
    """
    data = {"name": name}
    if fields:
        data["fields"] = fields
    return safe_post("create_structure", data)

@mcp.tool()
def find_bytes(pattern: str, start: str = None, end: str = None, limit: int = 100) -> list:
    """
    Search for bytes matching a pattern (supports ?? wildcards).

    Args:
        pattern: Hex byte pattern with optional wildcards, e.g. "00 48 ?? e9"
        start: Start address (optional, default: program min address)
        end: End address (optional, default: program max address)
        limit: Maximum number of results to return (default: 100)

    Returns:
        List of addresses where pattern was found

    Example:
        find_bytes("00 48 2d e9")  # Find ARM push instruction
        find_bytes("08 ?? ?? ??")  # Find pointers starting with 08
    """
    params = {"pattern": pattern, "limit": limit}
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    return safe_get("find_bytes", params)

@mcp.tool()
def find_instruction(mnemonic: str, operands: str = None, start: str = None, end: str = None, limit: int = 100) -> list:
    """
    Search for instructions matching mnemonic and optional operands.

    Args:
        mnemonic: Instruction mnemonic (e.g. "ldr", "bl", "mov")
        operands: Optional operand filter (substring match, e.g. "r0")
        start: Start address (optional)
        end: End address (optional)
        limit: Maximum number of results (default: 100)

    Returns:
        List of matching instructions with their addresses and containing functions

    Example:
        find_instruction("ldr", "r0")  # Find all "ldr r0, ..." instructions
        find_instruction("bl")         # Find all function calls
    """
    params = {"mnemonic": mnemonic, "limit": limit}
    if operands:
        params["operands"] = operands
    if start:
        params["start"] = start
    if end:
        params["end"] = end
    return safe_get("find_instruction", params)

@mcp.tool()
def get_instruction(address: str) -> str:
    """
    Get detailed information about an instruction at a specific address.

    Args:
        address: Target address in hex format

    Returns:
        Detailed instruction information including:
        - Mnemonic and operands
        - Instruction bytes
        - References
        - Fall-through address
        - Flow type

    Example:
        get_instruction("0x080012a4")
    """
    return "\n".join(safe_get("get_instruction", {"address": address}))

@mcp.tool()
def create_array(address: str, element_type: str, count: int) -> str:
    """
    Create an array of elements at the specified address.

    Args:
        address: Target address in hex format
        element_type: Data type name for array elements (e.g. "pointer", "undefined4")
        count: Number of elements in the array

    Returns:
        Success message with array details or error

    Example:
        create_array("0x08100000", "pointer", 50)  # Create array of 50 pointers
        create_array("0x08200000", "undefined1", 1024)  # Create 1KB byte array
    """
    return safe_post("create_array", {"address": address, "element_type": element_type, "count": str(count)})

@mcp.tool()
def get_symbol_at(address: str) -> str:
    """
    Get symbol information at a specific address.

    Args:
        address: Target address in hex format

    Returns:
        Symbol name(s) and type(s) at the address, or message if no symbol exists

    Example:
        get_symbol_at("0x08001234")
    """
    return "\n".join(safe_get("get_symbol_at", {"address": address}))

@mcp.tool()
def list_symbols(type: str = None, filter: str = None, offset: int = 0, limit: int = 100) -> list:
    """
    List symbols in the program with optional filtering.

    Args:
        type: Symbol type filter - "function", "label", "data", or "all" (default: all)
        filter: Name filter (substring match)
        offset: Pagination offset (default: 0)
        limit: Maximum number of results (default: 100)

    Returns:
        List of symbols with their addresses and types

    Example:
        list_symbols(type="label", filter="text")
    """
    params = {"offset": offset, "limit": limit}
    if type:
        params["type"] = type
    if filter:
        params["filter"] = filter
    return safe_get("list_symbols", params)

@mcp.tool()
def remove_symbol(address: str, name: str = None) -> str:
    """
    Remove symbol(s) at a specific address.

    Args:
        address: Target address in hex format
        name: Optional specific symbol name to remove (if not provided, removes all at address)

    Returns:
        Success or error message

    Example:
        remove_symbol("0x08001234", "old_label")
    """
    data = {"address": address}
    if name:
        data["name"] = name
    return safe_post("remove_symbol", data)

@mcp.tool()
def disassemble_range(start: str, end: str, limit: int = 100) -> list:
    """
    Disassemble instructions in an address range.

    Args:
        start: Start address in hex format
        end: End address in hex format
        limit: Maximum number of instructions to return (default: 100)

    Returns:
        List of instructions with their addresses

    Example:
        disassemble_range("0x08001000", "0x08001050")
    """
    return safe_get("disassemble_range", {"start": start, "end": end, "limit": limit})

@mcp.tool()
def get_function_containing(address: str) -> str:
    """
    Get information about the function containing a specific address.

    Args:
        address: Target address in hex format

    Returns:
        Function details including name, entry point, body range, and signature

    Example:
        get_function_containing("0x08001234")
    """
    return "\n".join(safe_get("get_function_containing", {"address": address}))

@mcp.tool()
def clear_listing(start: str, end: str) -> str:
    """
    Clear code units (instructions/data) in an address range.

    Use this before redefining data structures or fixing incorrect analysis.

    Args:
        start: Start address in hex format
        end: End address in hex format

    Returns:
        Success or error message

    Example:
        clear_listing("0x08100000", "0x08100100")
    """
    return safe_post("clear_listing", {"start": start, "end": end})

@mcp.tool()
def set_equate(address: str, name: str, value: int, operand_index: int = 0) -> str:
    """
    Set an equate (named constant) for an instruction operand.

    This replaces magic numbers with meaningful names in the disassembly.

    Args:
        address: Instruction address in hex format
        name: Name for the constant (e.g., "FRAME_TYPE_I")
        value: The numeric value this equate represents
        operand_index: Which operand to apply to (default: 0)

    Returns:
        Success or error message

    Example:
        # Replace "cmp r0, #0x14" with "cmp r0, #MSG_GAME_OVER"
        set_equate("0x08001234", "MSG_GAME_OVER", 0x14, 1)
    """
    return safe_post("set_equate", {
        "address": address,
        "name": name,
        "value": str(value),
        "operand_index": str(operand_index)
    })

@mcp.tool()
def create_enum(name: str, values: str = None) -> str:
    """
    Create an enumeration data type.

    Args:
        name: Enum name
        values: Comma-separated values in format:
                - "NAME=value,NAME=value,..." for explicit values
                - "NAME,NAME,..." for auto-increment from 0
                Example: "I_FRAME=0,P_FRAME=1,B_FRAME=2"
                Example: "STATE_IDLE,STATE_RUNNING,STATE_PAUSED" (auto: 0,1,2)

    Returns:
        Success message with enum details or error

    Example:
        create_enum("FrameType", "I_FRAME=0,P_FRAME=1,B_FRAME=2")
        create_enum("GameState", "IDLE,RUNNING,PAUSED,STOPPED")
    """
    data = {"name": name}
    if values:
        data["values"] = values
    return safe_post("create_enum", data)

@mcp.tool()
def apply_enum(address: str, enum_name: str, operand_index: int = 0) -> str:
    """
    Apply an enum to an instruction operand.

    This automatically creates equates for all enum values matching the operand.

    Args:
        address: Instruction address in hex format
        enum_name: Name of the enum to apply
        operand_index: Which operand to apply to (default: 0)

    Returns:
        Success or error message

    Example:
        # First create enum
        create_enum("FrameType", "I_FRAME=0,P_FRAME=1,B_FRAME=2")

        # Then apply it to replace numeric values
        apply_enum("0x08001234", "FrameType", 1)
    """
    return safe_post("apply_enum", {
        "address": address,
        "enum_name": enum_name,
        "operand_index": str(operand_index)
    })

@mcp.tool()
def get_data(address: str) -> str:
    """
    Get detailed information about data defined at an address.

    This is useful for inspecting codebooks, lookup tables, and other data structures.

    Args:
        address: Target address in hex format

    Returns:
        Data type, length, value, and other details

    Example:
        # Check if address has a data definition
        data_info = get_data("0x08100000")
        # Shows: Type, length, value, whether it's array/struct/pointer
    """
    return "\n".join(safe_get("get_data", {"address": address}))

@mcp.tool()
def create_string(address: str, length: int = None) -> str:
    """
    Create a string data type at the specified address.

    If length is not provided, automatically detects null-terminated string.

    Args:
        address: Target address in hex format
        length: Optional string length in bytes (auto-detect if not provided)

    Returns:
        Success message with string details or error

    Example:
        # Auto-detect string length
        create_string("0x08100000")

        # Explicit length
        create_string("0x08100000", 50)
    """
    data = {"address": address}
    if length is not None:
        data["length"] = str(length)
    return safe_post("create_string", data)

@mcp.tool()
def add_reference(from_address: str, to_address: str, ref_type: str = "DATA") -> str:
    """
    Add a reference from one address to another.

    Useful for marking relationships between code and data structures (like codebooks).

    Args:
        from_address: Source address in hex format
        to_address: Target address in hex format
        ref_type: Reference type - "DATA", "READ", "WRITE", "CODE", "CALL", "JUMP" (default: "DATA")

    Returns:
        Success or error message

    Example:
        # Mark that a function reads from a codebook
        add_reference("0x08001234", "0x08100000", "READ")

        # Mark a function call
        add_reference("0x08001234", "0x08005000", "CALL")
    """
    return safe_post("add_reference", {
        "from_address": from_address,
        "to_address": to_address,
        "ref_type": ref_type
    })

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()

