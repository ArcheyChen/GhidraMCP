package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.options.Options;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8080;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // Memory operations
        server.createContext("/read_memory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 16);
            String format = qparams.getOrDefault("format", "hex");
            sendResponse(exchange, readMemory(address, length, format));
        });

        server.createContext("/write_memory", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String data = params.get("data");
            boolean success = writeMemory(address, data);
            sendResponse(exchange, success ? "Memory written successfully" : "Failed to write memory");
        });

        // Program info
        server.createContext("/program_info", exchange -> {
            sendResponse(exchange, getProgramInfo());
        });

        // Bookmarks
        server.createContext("/create_bookmark", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String category = params.get("category");
            String comment = params.get("comment");
            boolean success = createBookmark(address, category, comment);
            sendResponse(exchange, success ? "Bookmark created successfully" : "Failed to create bookmark");
        });

        server.createContext("/list_bookmarks", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listBookmarks(offset, limit));
        });

        // Labels
        server.createContext("/create_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            boolean primary = Boolean.parseBoolean(params.getOrDefault("primary", "true"));
            boolean success = createLabel(address, name, primary);
            sendResponse(exchange, success ? "Label created successfully" : "Failed to create label");
        });

        // Function operations
        server.createContext("/create_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String result = createFunction(address, name);
            sendResponse(exchange, result);
        });

        server.createContext("/delete_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            boolean success = deleteFunction(address);
            sendResponse(exchange, success ? "Function deleted successfully" : "Failed to delete function");
        });

        // Data type operations
        server.createContext("/list_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDataTypes(offset, limit, filter));
        });

        server.createContext("/apply_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String dataTypeName = params.get("data_type");
            String result = applyDataType(address, dataTypeName);
            sendResponse(exchange, result);
        });

        server.createContext("/create_structure", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String fieldsJson = params.get("fields");
            String result = createStructure(name, fieldsJson);
            sendResponse(exchange, result);
        });

        // Search operations
        server.createContext("/find_bytes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            String startAddr = qparams.get("start");
            String endAddr = qparams.get("end");
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, findBytes(pattern, startAddr, endAddr, limit));
        });

        server.createContext("/find_instruction", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String mnemonic = qparams.get("mnemonic");
            String operands = qparams.get("operands");
            String startAddr = qparams.get("start");
            String endAddr = qparams.get("end");
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, findInstruction(mnemonic, operands, startAddr, endAddr, limit));
        });

        server.createContext("/get_instruction", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getInstructionDetails(address));
        });

        server.createContext("/create_array", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String elementType = params.get("element_type");
            int count = parseIntOrDefault(params.get("count"), 1);
            String result = createArray(address, elementType, count);
            sendResponse(exchange, result);
        });

        // Symbol operations
        server.createContext("/get_symbol_at", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getSymbolAt(address));
        });

        server.createContext("/list_symbols", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String type = qparams.get("type");
            String filter = qparams.get("filter");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listSymbols(type, filter, offset, limit));
        });

        server.createContext("/remove_symbol", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            boolean success = removeSymbol(address, name);
            sendResponse(exchange, success ? "Symbol removed successfully" : "Failed to remove symbol");
        });

        // Analysis operations
        server.createContext("/disassemble_range", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String start = qparams.get("start");
            String end = qparams.get("end");
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, disassembleRange(start, end, limit));
        });

        server.createContext("/get_function_containing", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionContainingAddress(address));
        });

        server.createContext("/clear_listing", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String start = params.get("start");
            String end = params.get("end");
            boolean success = clearListing(start, end);
            sendResponse(exchange, success ? "Listing cleared successfully" : "Failed to clear listing");
        });

        // Equate and Enum operations
        server.createContext("/set_equate", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            long value = Long.parseLong(params.getOrDefault("value", "0"));
            int opIndex = parseIntOrDefault(params.get("operand_index"), 0);
            boolean success = setEquate(address, name, value, opIndex);
            sendResponse(exchange, success ? "Equate set successfully" : "Failed to set equate");
        });

        server.createContext("/create_enum", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String values = params.get("values");
            String result = createEnum(name, values);
            sendResponse(exchange, result);
        });

        server.createContext("/apply_enum", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String enumName = params.get("enum_name");
            int opIndex = parseIntOrDefault(params.get("operand_index"), 0);
            boolean success = applyEnum(address, enumName, opIndex);
            sendResponse(exchange, success ? "Enum applied successfully" : "Failed to apply enum");
        });

        // Data operations
        server.createContext("/get_data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getData(address));
        });

        server.createContext("/create_string", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String lengthStr = params.get("length");
            Integer length = lengthStr != null && !lengthStr.isEmpty() ? Integer.parseInt(lengthStr) : null;
            String result = createString(address, length);
            sendResponse(exchange, result);
        });

        // Reference operations
        server.createContext("/add_reference", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String fromAddr = params.get("from_address");
            String toAddr = params.get("to_address");
            String refType = params.getOrDefault("ref_type", "DATA");
            boolean success = addReference(fromAddr, toAddr, refType);
            sendResponse(exchange, success ? "Reference added successfully" : "Failed to add reference");
        });

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    private boolean setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd = 
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                success.set(true);
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;
        
        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
        if (input == null) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
            return dataType;
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive)
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    // ----------------------------------------------------------------------------------
    // New API implementations
    // ----------------------------------------------------------------------------------

    /**
     * Read memory from a specified address
     */
    private String readMemory(String addressStr, int length, String format) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            byte[] bytes = new byte[length];
            int bytesRead = program.getMemory().getBytes(addr, bytes);

            if (bytesRead == 0) {
                return "No memory at address " + addressStr;
            }

            StringBuilder result = new StringBuilder();

            if ("hex".equalsIgnoreCase(format)) {
                // Hex dump format
                for (int i = 0; i < bytesRead; i++) {
                    if (i > 0 && i % 16 == 0) {
                        result.append("\n");
                    }
                    result.append(String.format("%02x ", bytes[i] & 0xFF));
                }
            } else if ("ascii".equalsIgnoreCase(format)) {
                // ASCII representation
                for (int i = 0; i < bytesRead; i++) {
                    char c = (char) (bytes[i] & 0xFF);
                    if (c >= 32 && c < 127) {
                        result.append(c);
                    } else {
                        result.append('.');
                    }
                }
            } else if ("both".equalsIgnoreCase(format)) {
                // Hex + ASCII side by side
                for (int i = 0; i < bytesRead; i += 16) {
                    // Address
                    result.append(String.format("%08x: ", addr.getOffset() + i));

                    // Hex bytes
                    for (int j = 0; j < 16 && (i + j) < bytesRead; j++) {
                        result.append(String.format("%02x ", bytes[i + j] & 0xFF));
                    }

                    // Padding
                    for (int j = bytesRead - i; j < 16; j++) {
                        result.append("   ");
                    }

                    result.append(" |");

                    // ASCII
                    for (int j = 0; j < 16 && (i + j) < bytesRead; j++) {
                        char c = (char) (bytes[i + j] & 0xFF);
                        result.append((c >= 32 && c < 127) ? c : '.');
                    }

                    result.append("|\n");
                }
            }

            return result.toString();
        } catch (Exception e) {
            return "Error reading memory: " + e.getMessage();
        }
    }

    /**
     * Write memory to a specified address
     */
    private boolean writeMemory(String addressStr, String hexData) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || hexData == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Write memory");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);

                    // Parse hex string to bytes
                    String cleanHex = hexData.replaceAll("\\s+", "");
                    byte[] bytes = new byte[cleanHex.length() / 2];
                    for (int i = 0; i < bytes.length; i++) {
                        bytes[i] = (byte) Integer.parseInt(cleanHex.substring(i * 2, i * 2 + 2), 16);
                    }

                    program.getMemory().setBytes(addr, bytes);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error writing memory", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            Msg.error(this, "Failed to execute write memory on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Get program information
     */
    private String getProgramInfo() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder info = new StringBuilder();

        info.append("Program Name: ").append(program.getName()).append("\n");
        info.append("Executable Path: ").append(program.getExecutablePath()).append("\n");
        info.append("Language: ").append(program.getLanguage().getLanguageID()).append("\n");
        info.append("Compiler: ").append(program.getCompiler()).append("\n");
        info.append("Processor: ").append(program.getLanguage().getProcessor()).append("\n");
        info.append("Endian: ").append(program.getLanguage().isBigEndian() ? "Big" : "Little").append("\n");
        info.append("Address Size: ").append(program.getLanguage().getDefaultSpace().getSize()).append(" bits\n");
        info.append("Min Address: ").append(program.getMinAddress()).append("\n");
        info.append("Max Address: ").append(program.getMaxAddress()).append("\n");
        info.append("Image Base: ").append(program.getImageBase()).append("\n");

        // Memory info
        long totalBytes = 0;
        int blockCount = 0;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            totalBytes += block.getSize();
            blockCount++;
        }
        info.append("Memory Blocks: ").append(blockCount).append("\n");
        info.append("Total Memory: ").append(totalBytes).append(" bytes\n");

        // Function count
        info.append("Functions: ").append(program.getFunctionManager().getFunctionCount()).append("\n");

        // Symbol count
        info.append("Symbols: ").append(program.getSymbolTable().getNumSymbols()).append("\n");

        return info.toString();
    }

    /**
     * Create a bookmark at specified address
     */
    private boolean createBookmark(String addressStr, String category, String comment) {
        Program program = getCurrentProgram();
        if (program == null || addressStr == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create bookmark");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getBookmarkManager().setBookmark(
                        addr,
                        category != null ? category : "Analysis",
                        "MCP",
                        comment != null ? comment : ""
                    );
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error creating bookmark", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            Msg.error(this, "Failed to create bookmark on Swing thread", e);
        }

        return success.get();
    }

    /**
     * List all bookmarks
     */
    private String listBookmarks(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> bookmarks = new ArrayList<>();

        Iterator<ghidra.program.model.listing.Bookmark> iter = program.getBookmarkManager().getBookmarksIterator();
        while (iter.hasNext()) {
            ghidra.program.model.listing.Bookmark bookmark = iter.next();
            String line = String.format("%s [%s/%s]: %s",
                bookmark.getAddress(),
                bookmark.getCategory(),
                bookmark.getType(),
                bookmark.getComment()
            );
            bookmarks.add(line);
        }

        return paginateList(bookmarks, offset, limit);
    }

    /**
     * Create a label at specified address
     */
    private boolean createLabel(String addressStr, String name, boolean primary) {
        Program program = getCurrentProgram();
        if (program == null || addressStr == null || name == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create label");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Symbol symbol = program.getSymbolTable().createLabel(
                        addr, name, SourceType.USER_DEFINED
                    );

                    if (primary && symbol != null) {
                        symbol.setPrimary();
                    }

                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error creating label", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            Msg.error(this, "Failed to create label on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Create a function at specified address
     */
    private String createFunction(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null) return "Address is required";

        final StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);

                    // Check if function already exists
                    Function existing = program.getFunctionManager().getFunctionAt(addr);
                    if (existing != null) {
                        result.append("Function already exists at ").append(addressStr);
                        return;
                    }

                    // Create function
                    Function func = program.getFunctionManager().createFunction(
                        name, addr, null, SourceType.USER_DEFINED
                    );

                    if (func != null) {
                        result.append("Function created: ").append(func.getName())
                              .append(" at ").append(func.getEntryPoint());
                        success = true;
                    } else {
                        result.append("Failed to create function");
                    }
                } catch (Exception e) {
                    result.append("Error creating function: ").append(e.getMessage());
                    Msg.error(this, "Error creating function", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            return "Failed to create function on Swing thread: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Delete a function at specified address
     */
    private boolean deleteFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null || addressStr == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete function");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Function func = getFunctionForAddress(program, addr);

                    if (func != null) {
                        program.getFunctionManager().removeFunction(addr);
                        success.set(true);
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error deleting function", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            Msg.error(this, "Failed to delete function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * List all data types
     */
    private String listDataTypes(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> types = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();

        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            String typeName = dt.getPathName();

            if (filter == null || typeName.toLowerCase().contains(filter.toLowerCase())) {
                types.add(typeName + " [" + dt.getLength() + " bytes]");
            }
        }

        Collections.sort(types);
        return paginateList(types, offset, limit);
    }

    /**
     * Apply a data type at specified address
     */
    private String applyDataType(String addressStr, String dataTypeName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || dataTypeName == null) return "Address and data type are required";

        final StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Apply data type");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    DataTypeManager dtm = program.getDataTypeManager();

                    DataType dataType = findDataTypeByNameInAllCategories(dtm, dataTypeName);
                    if (dataType == null) {
                        result.append("Data type not found: ").append(dataTypeName);
                        return;
                    }

                    // Clear existing data
                    program.getListing().clearCodeUnits(addr, addr.add(dataType.getLength() - 1), false);

                    // Apply data type
                    Data data = program.getListing().createData(addr, dataType);

                    if (data != null) {
                        result.append("Data type applied: ").append(dataType.getName())
                              .append(" at ").append(addr)
                              .append(" (").append(dataType.getLength()).append(" bytes)");
                        success = true;
                    } else {
                        result.append("Failed to apply data type");
                    }
                } catch (Exception e) {
                    result.append("Error applying data type: ").append(e.getMessage());
                    Msg.error(this, "Error applying data type", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            return "Failed to apply data type on Swing thread: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Create a structure data type
     */
    private String createStructure(String name, String fieldsJson) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null) return "Structure name is required";

        final StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create structure");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Create structure
                    ghidra.program.model.data.Structure struct = new ghidra.program.model.data.StructureDataType(name, 0);

                    // Parse fields if provided (format: "fieldName:typeName,fieldName:typeName,...")
                    if (fieldsJson != null && !fieldsJson.isEmpty()) {
                        String[] fields = fieldsJson.split(",");
                        for (String field : fields) {
                            String[] parts = field.trim().split(":");
                            if (parts.length == 2) {
                                String fieldName = parts[0].trim();
                                String typeName = parts[1].trim();

                                DataType fieldType = findDataTypeByNameInAllCategories(dtm, typeName);
                                if (fieldType == null) {
                                    // Try built-in types
                                    fieldType = dtm.getDataType("/" + typeName);
                                }

                                if (fieldType != null) {
                                    struct.add(fieldType, fieldName, null);
                                } else {
                                    result.append("Warning: Unknown type ").append(typeName)
                                          .append(" for field ").append(fieldName).append("\n");
                                }
                            }
                        }
                    }

                    // Add to data type manager
                    DataType addedType = dtm.addDataType(struct, null);

                    result.append("Structure created: ").append(addedType.getPathName())
                          .append(" (").append(addedType.getLength()).append(" bytes)");
                    success = true;
                } catch (Exception e) {
                    result.append("Error creating structure: ").append(e.getMessage());
                    Msg.error(this, "Error creating structure", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            return "Failed to create structure on Swing thread: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Find bytes matching a pattern (supports wildcards with ??)
     */
    private String findBytes(String pattern, String startAddrStr, String endAddrStr, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (pattern == null || pattern.isEmpty()) return "Pattern is required";

        try {
            // Parse pattern - support space-separated hex bytes with ?? wildcards
            String[] patternParts = pattern.trim().split("\\s+");
            byte[] searchBytes = new byte[patternParts.length];
            byte[] maskBytes = new byte[patternParts.length];

            for (int i = 0; i < patternParts.length; i++) {
                String part = patternParts[i];
                if (part.equals("??") || part.equals("?")) {
                    searchBytes[i] = 0;
                    maskBytes[i] = 0;  // Wildcard: don't check this byte
                } else {
                    searchBytes[i] = (byte) Integer.parseInt(part, 16);
                    maskBytes[i] = (byte) 0xFF;  // Check this byte
                }
            }

            // Determine search range
            Address startAddr = startAddrStr != null && !startAddrStr.isEmpty()
                ? program.getAddressFactory().getAddress(startAddrStr)
                : program.getMinAddress();

            Address endAddr = endAddrStr != null && !endAddrStr.isEmpty()
                ? program.getAddressFactory().getAddress(endAddrStr)
                : program.getMaxAddress();

            // Search
            List<String> results = new ArrayList<>();
            ghidra.program.model.mem.Memory memory = program.getMemory();

            Address currentAddr = startAddr;
            int found = 0;

            while (currentAddr != null && currentAddr.compareTo(endAddr) <= 0 && found < limit) {
                Address matchAddr = memory.findBytes(currentAddr, endAddr, searchBytes, maskBytes, true, new ConsoleTaskMonitor());

                if (matchAddr == null) {
                    break;
                }

                // Found a match
                Function func = program.getFunctionManager().getFunctionContaining(matchAddr);
                String funcName = func != null ? " in " + func.getName() : "";

                results.add(String.format("%s%s", matchAddr, funcName));
                found++;

                // Move to next byte after match
                currentAddr = matchAddr.add(1);
            }

            if (results.isEmpty()) {
                return "No matches found for pattern: " + pattern;
            }

            return String.join("\n", results);

        } catch (Exception e) {
            return "Error searching bytes: " + e.getMessage();
        }
    }

    /**
     * Find instructions matching mnemonic and optional operands
     */
    private String findInstruction(String mnemonic, String operands, String startAddrStr, String endAddrStr, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (mnemonic == null || mnemonic.isEmpty()) return "Mnemonic is required";

        try {
            Address startAddr = startAddrStr != null && !startAddrStr.isEmpty()
                ? program.getAddressFactory().getAddress(startAddrStr)
                : program.getMinAddress();

            Address endAddr = endAddrStr != null && !endAddrStr.isEmpty()
                ? program.getAddressFactory().getAddress(endAddrStr)
                : program.getMaxAddress();

            List<String> results = new ArrayList<>();
            Listing listing = program.getListing();
            InstructionIterator instructions = listing.getInstructions(startAddr, true);

            int found = 0;
            while (instructions.hasNext() && found < limit) {
                Instruction instr = instructions.next();

                if (instr.getAddress().compareTo(endAddr) > 0) {
                    break;
                }

                // Check mnemonic
                if (!instr.getMnemonicString().equalsIgnoreCase(mnemonic)) {
                    continue;
                }

                // Check operands if specified
                if (operands != null && !operands.isEmpty()) {
                    String instrOperands = instr.getDefaultOperandRepresentation(0);
                    for (int i = 1; i < instr.getNumOperands(); i++) {
                        instrOperands += ", " + instr.getDefaultOperandRepresentation(i);
                    }

                    if (!instrOperands.toLowerCase().contains(operands.toLowerCase())) {
                        continue;
                    }
                }

                // Found matching instruction
                Function func = program.getFunctionManager().getFunctionContaining(instr.getAddress());
                String funcName = func != null ? " in " + func.getName() : "";

                results.add(String.format("%s: %s%s",
                    instr.getAddress(),
                    instr.toString(),
                    funcName
                ));

                found++;
            }

            if (results.isEmpty()) {
                String searchStr = operands != null ? mnemonic + " " + operands : mnemonic;
                return "No matches found for instruction: " + searchStr;
            }

            return String.join("\n", results);

        } catch (Exception e) {
            return "Error searching instructions: " + e.getMessage();
        }
    }

    /**
     * Get detailed information about an instruction at address
     */
    private String getInstructionDetails(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Instruction instr = program.getListing().getInstructionAt(addr);

            if (instr == null) {
                return "No instruction at address " + addressStr;
            }

            StringBuilder details = new StringBuilder();

            details.append("Address: ").append(addr).append("\n");
            details.append("Mnemonic: ").append(instr.getMnemonicString()).append("\n");
            details.append("Full: ").append(instr.toString()).append("\n");
            details.append("Length: ").append(instr.getLength()).append(" bytes\n");

            // Operands
            int numOperands = instr.getNumOperands();
            if (numOperands > 0) {
                details.append("Operands: ");
                for (int i = 0; i < numOperands; i++) {
                    if (i > 0) details.append(", ");
                    details.append(instr.getDefaultOperandRepresentation(i));
                }
                details.append("\n");
            }

            // References
            Reference[] refs = instr.getReferencesFrom();
            if (refs.length > 0) {
                details.append("References:\n");
                for (Reference ref : refs) {
                    details.append("  -> ").append(ref.getToAddress())
                           .append(" [").append(ref.getReferenceType().getName()).append("]\n");
                }
            }

            // Fall-through
            Address fallThrough = instr.getFallThrough();
            if (fallThrough != null) {
                details.append("Fall-through: ").append(fallThrough).append("\n");
            }

            // Flow type
            details.append("Flow: ").append(instr.getFlowType()).append("\n");

            // Bytes
            details.append("Bytes: ");
            byte[] bytes = instr.getBytes();
            for (byte b : bytes) {
                details.append(String.format("%02x ", b & 0xFF));
            }
            details.append("\n");

            return details.toString();

        } catch (Exception e) {
            return "Error getting instruction details: " + e.getMessage();
        }
    }

    /**
     * Create an array of elements at the specified address
     */
    private String createArray(String addressStr, String elementTypeName, int count) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || elementTypeName == null) return "Address and element type are required";
        if (count <= 0) return "Count must be positive";

        final StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create array");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Find element data type
                    DataType elementType = findDataTypeByNameInAllCategories(dtm, elementTypeName);
                    if (elementType == null) {
                        elementType = dtm.getDataType("/" + elementTypeName);
                    }

                    if (elementType == null) {
                        result.append("Element type not found: ").append(elementTypeName);
                        return;
                    }

                    // Create array type
                    ghidra.program.model.data.Array arrayType = new ghidra.program.model.data.ArrayDataType(
                        elementType, count, elementType.getLength()
                    );

                    // Clear existing data
                    int arrayLength = count * elementType.getLength();
                    program.getListing().clearCodeUnits(addr, addr.add(arrayLength - 1), false);

                    // Apply array
                    Data data = program.getListing().createData(addr, arrayType);

                    if (data != null) {
                        result.append("Array created: ").append(count)
                              .append(" x ").append(elementType.getName())
                              .append(" at ").append(addr)
                              .append(" (").append(arrayLength).append(" bytes total)");
                        success = true;
                    } else {
                        result.append("Failed to create array");
                    }

                } catch (Exception e) {
                    result.append("Error creating array: ").append(e.getMessage());
                    Msg.error(this, "Error creating array", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            return "Failed to create array on Swing thread: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Get symbol at specified address
     */
    private String getSymbolAt(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Symbol[] symbols = program.getSymbolTable().getSymbols(addr);

            if (symbols.length == 0) {
                return "No symbol at address " + addressStr;
            }

            StringBuilder result = new StringBuilder();
            for (Symbol symbol : symbols) {
                result.append(symbol.getName())
                      .append(" [").append(symbol.getSymbolType()).append("]")
                      .append(symbol.isPrimary() ? " (primary)" : "")
                      .append("\n");
            }

            return result.toString().trim();

        } catch (Exception e) {
            return "Error getting symbol: " + e.getMessage();
        }
    }

    /**
     * List symbols with optional filtering
     */
    private String listSymbols(String type, String filter, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> results = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();

        try {
            SymbolIterator symbols = symbolTable.getAllSymbols(true);

            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();

                // Filter by type
                if (type != null && !type.isEmpty() && !type.equalsIgnoreCase("all")) {
                    SymbolType symType = symbol.getSymbolType();
                    if (type.equalsIgnoreCase("function") && symType != SymbolType.FUNCTION) continue;
                    if (type.equalsIgnoreCase("label") && symType != SymbolType.LABEL) continue;
                    if (type.equalsIgnoreCase("data") && symType != SymbolType.GLOBAL) continue;
                }

                // Filter by name
                if (filter != null && !filter.isEmpty()) {
                    if (!symbol.getName().toLowerCase().contains(filter.toLowerCase())) {
                        continue;
                    }
                }

                String line = String.format("%s: %s [%s]%s",
                    symbol.getAddress(),
                    symbol.getName(),
                    symbol.getSymbolType(),
                    symbol.isPrimary() ? " (primary)" : ""
                );
                results.add(line);
            }

        } catch (Exception e) {
            return "Error listing symbols: " + e.getMessage();
        }

        return paginateList(results, offset, limit);
    }

    /**
     * Remove symbol at address
     */
    private boolean removeSymbol(String addressStr, String name) {
        Program program = getCurrentProgram();
        if (program == null || addressStr == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Remove symbol");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Symbol[] symbols = program.getSymbolTable().getSymbols(addr);

                    for (Symbol symbol : symbols) {
                        if (name == null || name.isEmpty() || symbol.getName().equals(name)) {
                            symbol.delete();
                            success.set(true);
                            if (name != null) break;  // Only remove the specified one
                        }
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error removing symbol", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            Msg.error(this, "Failed to remove symbol on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Disassemble a range of addresses
     */
    private String disassembleRange(String startAddrStr, String endAddrStr, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (startAddrStr == null || endAddrStr == null) return "Start and end addresses are required";

        try {
            Address startAddr = program.getAddressFactory().getAddress(startAddrStr);
            Address endAddr = program.getAddressFactory().getAddress(endAddrStr);

            List<String> results = new ArrayList<>();
            Listing listing = program.getListing();
            InstructionIterator instructions = listing.getInstructions(startAddr, true);

            int count = 0;
            while (instructions.hasNext() && count < limit) {
                Instruction instr = instructions.next();

                if (instr.getAddress().compareTo(endAddr) > 0) {
                    break;
                }

                results.add(String.format("%s: %s", instr.getAddress(), instr.toString()));
                count++;
            }

            if (results.isEmpty()) {
                return "No instructions in range";
            }

            return String.join("\n", results);

        } catch (Exception e) {
            return "Error disassembling range: " + e.getMessage();
        }
    }

    /**
     * Get function containing the specified address
     */
    private String getFunctionContainingAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionContaining(addr);

            if (func == null) {
                return "No function contains address " + addressStr;
            }

            StringBuilder result = new StringBuilder();
            result.append("Function: ").append(func.getName()).append("\n");
            result.append("Entry: ").append(func.getEntryPoint()).append("\n");
            result.append("Body: ").append(func.getBody().getMinAddress())
                  .append(" - ").append(func.getBody().getMaxAddress()).append("\n");
            result.append("Signature: ").append(func.getPrototypeString(false, false));

            return result.toString();

        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
    }

    /**
     * Clear code units in a range
     */
    private boolean clearListing(String startAddrStr, String endAddrStr) {
        Program program = getCurrentProgram();
        if (program == null || startAddrStr == null || endAddrStr == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clear listing");
                try {
                    Address startAddr = program.getAddressFactory().getAddress(startAddrStr);
                    Address endAddr = program.getAddressFactory().getAddress(endAddrStr);

                    program.getListing().clearCodeUnits(startAddr, endAddr, false);
                    success.set(true);

                } catch (Exception e) {
                    Msg.error(this, "Error clearing listing", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            Msg.error(this, "Failed to clear listing on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set an equate (named constant) at an instruction operand
     */
    private boolean setEquate(String addressStr, String name, long value, int operandIndex) {
        Program program = getCurrentProgram();
        if (program == null || addressStr == null || name == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set equate");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    EquateTable equateTable = program.getEquateTable();

                    // Create or get equate
                    Equate equate = equateTable.getEquate(name);
                    if (equate == null) {
                        equate = equateTable.createEquate(name, value);
                    }

                    // Apply to the operand at the address
                    equate.addReference(addr, operandIndex);
                    success.set(true);

                } catch (Exception e) {
                    Msg.error(this, "Error setting equate", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            Msg.error(this, "Failed to set equate on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Create an enum data type
     */
    private String createEnum(String name, String valuesStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null) return "Enum name is required";

        final StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create enum");
                boolean success = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Create enum
                    ghidra.program.model.data.Enum enumType = new ghidra.program.model.data.EnumDataType(name, 4);

                    // Parse values if provided (format: "NAME=value,NAME=value,..." or "NAME,NAME,..." for auto-increment)
                    if (valuesStr != null && !valuesStr.isEmpty()) {
                        String[] entries = valuesStr.split(",");
                        long autoValue = 0;

                        for (String entry : entries) {
                            entry = entry.trim();
                            String[] parts = entry.split("=");

                            if (parts.length == 2) {
                                // Explicit value: "NAME=123"
                                String entryName = parts[0].trim();
                                long entryValue = Long.parseLong(parts[1].trim());
                                enumType.add(entryName, entryValue);
                            } else if (parts.length == 1) {
                                // Auto-increment: "NAME"
                                String entryName = parts[0].trim();
                                enumType.add(entryName, autoValue);
                                autoValue++;
                            }
                        }
                    }

                    // Add to data type manager
                    DataType addedType = dtm.addDataType(enumType, null);

                    result.append("Enum created: ").append(addedType.getPathName())
                          .append(" with ").append(enumType.getCount()).append(" values");
                    success = true;

                } catch (Exception e) {
                    result.append("Error creating enum: ").append(e.getMessage());
                    Msg.error(this, "Error creating enum", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            return "Failed to create enum on Swing thread: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Apply an enum to an instruction operand
     */
    private boolean applyEnum(String addressStr, String enumName, int operandIndex) {
        Program program = getCurrentProgram();
        if (program == null || addressStr == null || enumName == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Apply enum");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Find enum type
                    DataType enumType = findDataTypeByNameInAllCategories(dtm, enumName);
                    if (enumType == null || !(enumType instanceof ghidra.program.model.data.Enum)) {
                        Msg.error(this, "Enum not found: " + enumName);
                        return;
                    }

                    // Get the instruction
                    Instruction instr = program.getListing().getInstructionAt(addr);
                    if (instr == null) {
                        Msg.error(this, "No instruction at address: " + addressStr);
                        return;
                    }

                    // Get the scalar value from the operand
                    int numOperands = instr.getNumOperands();
                    if (operandIndex >= numOperands) {
                        Msg.error(this, "Invalid operand index: " + operandIndex);
                        return;
                    }

                    Object[] opObjects = instr.getOpObjects(operandIndex);
                    for (Object obj : opObjects) {
                        if (obj instanceof Scalar) {
                            Scalar scalar = (Scalar) obj;
                            long value = scalar.getValue();

                            // Create equate from enum entry
                            ghidra.program.model.data.Enum enumData = (ghidra.program.model.data.Enum) enumType;
                            String entryName = enumData.getName(value);

                            if (entryName != null) {
                                EquateTable equateTable = program.getEquateTable();
                                Equate equate = equateTable.getEquate(entryName);
                                if (equate == null) {
                                    equate = equateTable.createEquate(entryName, value);
                                }
                                equate.addReference(addr, operandIndex);
                                success.set(true);
                            }
                        }
                    }

                } catch (Exception e) {
                    Msg.error(this, "Error applying enum", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            Msg.error(this, "Failed to apply enum on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Get data details at specified address
     */
    private String getData(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Data data = program.getListing().getDataAt(addr);

            if (data == null) {
                return "No data defined at address " + addressStr;
            }

            StringBuilder result = new StringBuilder();
            result.append("Address: ").append(addr).append("\n");
            result.append("Type: ").append(data.getDataType().getName()).append("\n");
            result.append("Type Path: ").append(data.getDataType().getPathName()).append("\n");
            result.append("Length: ").append(data.getLength()).append(" bytes\n");

            // Try to get value representation
            Object value = data.getValue();
            if (value != null) {
                result.append("Value: ").append(value).append("\n");
            }

            // Get representation
            String repr = data.getDefaultValueRepresentation();
            if (repr != null && !repr.isEmpty()) {
                result.append("Representation: ").append(repr).append("\n");
            }

            // Check if it's an array
            if (data.isArray()) {
                result.append("Array: ").append(data.getNumComponents()).append(" elements\n");
            }

            // Check if it's a structure
            if (data.isStructure()) {
                result.append("Structure: ").append(data.getNumComponents()).append(" components\n");
            }

            // Check if it's a pointer
            if (data.isPointer()) {
                result.append("Pointer to: ");
                Reference[] refs = data.getReferencesFrom();
                if (refs.length > 0) {
                    result.append(refs[0].getToAddress());
                }
                result.append("\n");
            }

            return result.toString();

        } catch (Exception e) {
            return "Error getting data: " + e.getMessage();
        }
    }

    /**
     * Create a string at specified address
     */
    private String createString(String addressStr, Integer length) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        final StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create string");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Get string data type
                    DataType stringType = dtm.getDataType("/string");
                    if (stringType == null) {
                        // Fallback to creating undefined string
                        stringType = ghidra.program.model.data.StringDataType.dataType;
                    }

                    // Clear existing data
                    if (length != null) {
                        program.getListing().clearCodeUnits(addr, addr.add(length - 1), false);
                    } else {
                        // Auto-detect string length by scanning for null terminator
                        ghidra.program.model.mem.Memory memory = program.getMemory();
                        int maxLen = 1024;  // Max string length to scan
                        int actualLen = 0;

                        for (int i = 0; i < maxLen; i++) {
                            try {
                                byte b = memory.getByte(addr.add(i));
                                actualLen++;
                                if (b == 0) break;
                            } catch (Exception e) {
                                break;
                            }
                        }

                        if (actualLen > 0) {
                            program.getListing().clearCodeUnits(addr, addr.add(actualLen - 1), false);
                        }
                    }

                    // Create string data
                    Data data = program.getListing().createData(addr, stringType);

                    if (data != null) {
                        result.append("String created at ").append(addr)
                              .append(" (").append(data.getLength()).append(" bytes)\n");

                        // Try to show the string value
                        Object value = data.getValue();
                        if (value != null) {
                            result.append("Value: \"").append(value.toString()).append("\"");
                        }
                        success = true;
                    } else {
                        result.append("Failed to create string");
                    }

                } catch (Exception e) {
                    result.append("Error creating string: ").append(e.getMessage());
                    Msg.error(this, "Error creating string", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });
        } catch (Exception e) {
            return "Failed to create string on Swing thread: " + e.getMessage();
        }

        return result.toString();
    }

    /**
     * Add a reference from one address to another
     */
    private boolean addReference(String fromAddrStr, String toAddrStr, String refTypeStr) {
        Program program = getCurrentProgram();
        if (program == null || fromAddrStr == null || toAddrStr == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add reference");
                try {
                    Address fromAddr = program.getAddressFactory().getAddress(fromAddrStr);
                    Address toAddr = program.getAddressFactory().getAddress(toAddrStr);

                    // Parse reference type
                    RefType refType;
                    switch (refTypeStr.toUpperCase()) {
                        case "DATA":
                            refType = RefType.DATA;
                            break;
                        case "READ":
                            refType = RefType.READ;
                            break;
                        case "WRITE":
                            refType = RefType.WRITE;
                            break;
                        case "CODE":
                        case "CALL":
                            refType = RefType.UNCONDITIONAL_CALL;
                            break;
                        case "JUMP":
                            refType = RefType.UNCONDITIONAL_JUMP;
                            break;
                        default:
                            refType = RefType.DATA;
                    }

                    // Add reference
                    ReferenceManager refMgr = program.getReferenceManager();
                    Reference ref = refMgr.addMemoryReference(fromAddr, toAddr, refType, SourceType.USER_DEFINED, 0);

                    success.set(ref != null);

                } catch (Exception e) {
                    Msg.error(this, "Error adding reference", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            Msg.error(this, "Failed to add reference on Swing thread", e);
        }

        return success.get();
    }

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
