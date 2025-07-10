import time
import re
import json
import uuid
from collections import defaultdict, deque
import requests
import anthropic
from binaryninja import PluginCommand, log_info, DisassemblySettings, DisassemblyOption, Settings, BackgroundTaskThread

disass_settings = DisassemblySettings()
disass_settings.set_option(DisassemblyOption.ShowAddress, False)
disass_settings.set_option(DisassemblyOption.WaitForIL, True)

call_graph = defaultdict(set)
seen_functions = set()

class ClaudeNameAllFunctions(BackgroundTaskThread):
    def __init__(self, bv):
        super().__init__(f"Consulting Claude on functions in {bv.file.filename}")
        self.bv = bv

    def run(self):
        self.start_analysis(self.bv)

    def cancel(self):
        log_info("Analysis cancelled.")
        super().cancel()

    def start_analysis(self, bv):
        api_key = Settings().get_string("ClaNaFu.api_key")
        if not api_key:
            log_info("Please set your Claude API key in the plugin settings.")
            return

        # Get the API mode setting
        use_batch_mode = Settings().get_bool("ClaNaFu.use_batch_mode")
        log_info(f"Using {'batch' if use_batch_mode else 'normal'} API mode")

        start_time = time.time()
        for function in bv.functions:
            self.build_call_graph(function)
        log_info(f"Built call graph of {len(seen_functions)} functions in {time.time() - start_time:.2f} seconds")

        start_time = time.time()
        if use_batch_mode:
            self.analyze_call_graph_batch()
        else:
            self.analyze_call_graph_normal()
        log_info(f"Analyzed call graph in {time.time() - start_time:.2f} seconds")

    def build_call_graph(self, function):
        if function in seen_functions:
            return
        seen_functions.add(function)
        call_graph[function] = set(function.callees)
        for callee in function.callees:
            self.build_call_graph(callee)

    def find_ready_functions_with_cycle_breaking(self, analyzed_functions):
        """Find functions ready for analysis, breaking cycles by picking one function"""
        ready_functions = []
        
        # First, find functions that are naturally ready (no cycles)
        naturally_ready = []
        for func in call_graph:
            if func in analyzed_functions:
                continue
                
            if func.name.startswith("_") or "sub_" not in func.name:
                analyzed_functions.add(func)
                continue
            
            # Check if all callees are analyzed (excluding self-recursive calls)
            all_callees_analyzed = True
            for callee in call_graph[func]:
                if callee == func:  # Skip self-recursive calls
                    continue
                    
                if (not callee.name.startswith("_") and 
                    "sub_" in callee.name and 
                    callee not in analyzed_functions):
                    all_callees_analyzed = False
                    break
            
            if all_callees_analyzed:
                naturally_ready.append(func)
        
        # If we found naturally ready functions, return them
        if naturally_ready:
            return naturally_ready
        
        # No naturally ready functions - we have cycles to break
        # Find the smallest unanalyzed SCC and pick one function from it
        sccs = self.find_strongly_connected_components()
        
        # Find unanalyzed SCCs that need naming
        unanalyzed_sccs = []
        for scc in sccs:
            if any(func in analyzed_functions for func in scc):
                continue
                
            needs_naming = [func for func in scc if not func.name.startswith("_") and "sub_" in func.name]
            if needs_naming:
                unanalyzed_sccs.append((scc, needs_naming))
        
        if not unanalyzed_sccs:
            return []
        
        # Pick the SCC with the fewest functions that need naming
        smallest_scc, functions_needing_naming = min(unanalyzed_sccs, key=lambda x: len(x[1]))
        
        # From that SCC, pick the function with the most callees to break the cycle
        # This gives Claude the most context - if a function calls 20 things and we know
        # 19 of them, Claude can still make a good inference about what it does
        cycle_breaker = max(functions_needing_naming, key=lambda f: len(call_graph[f]))
        
        log_info(f"Breaking cycle by analyzing {cycle_breaker.name} first (SCC size: {len(smallest_scc)})")
        
        return [cycle_breaker]

    def analyze_call_graph_normal(self):
        """Analyze call graph using normal API calls"""
        client = anthropic.Anthropic(api_key=Settings().get_string("ClaNaFu.api_key"))
        
        # Track analysis state
        analyzed_functions = set()
        good_results = 0
        bad_results = 0
        
        # Continue until all functions are analyzed
        while True:
            # Find functions ready for analysis (with cycle breaking)
            ready_functions = self.find_ready_functions_with_cycle_breaking(analyzed_functions)
            
            if not ready_functions:
                break  # No more functions to analyze
                
            log_info(f"Found {len(ready_functions)} functions ready for analysis")
            
            # Process this batch of ready functions using normal API
            batch_results = self.process_normal_api(client, ready_functions)
            
            # Update function names and tracking
            for func, new_name in batch_results.items():
                if new_name:
                    func.name = new_name
                    analyzed_functions.add(func)
                    good_results += 1
                else:
                    analyzed_functions.add(func)
                    bad_results += 1
            
            # Update analysis after each batch
            if batch_results:
                self.bv.update_analysis()
        
        log_info(f"Updated {good_results} functions with new names and failed on {bad_results} functions.")

    def analyze_call_graph_batch(self):
        """Analyze call graph using batch API"""
        client = anthropic.Anthropic(api_key=Settings().get_string("ClaNaFu.api_key"))
        
        # Track analysis state
        analyzed_functions = set()
        good_results = 0
        bad_results = 0
        
        # Continue until all functions are analyzed
        while True:
            # Find functions ready for analysis (with cycle breaking)
            ready_functions = self.find_ready_functions_with_cycle_breaking(analyzed_functions)
            
            if not ready_functions:
                break  # No more functions to analyze
                
            log_info(f"Found {len(ready_functions)} functions ready for analysis")
            
            # Process this batch of ready functions using batch API
            batch_results = self.process_batch_api(client, ready_functions)
            
            # Update function names and tracking
            for func, new_name in batch_results.items():
                if new_name:
                    func.name = new_name
                    analyzed_functions.add(func)
                    good_results += 1
                else:
                    analyzed_functions.add(func)
                    bad_results += 1
        
        log_info(f"Updated {good_results} functions with new names and failed on {bad_results} functions.")

    def process_normal_api(self, client, functions):
        """Process functions using normal API calls"""
        if not functions:
            return {}
        
        results = {}
        
        for func in functions:
            try:
                func_prototype = "".join(str(t) for t in func.type_tokens)
                pseudo_c = func.pseudo_c
                lines = pseudo_c.get_linear_lines(func.hlil.root)
                func_body = "\n".join(str(line) for line in lines)
                code = func_prototype + "\n" + func_body

                message = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=50,
                    temperature=0,
                    system=f"Analyze the decompiled function from a {self.bv.platform} {self.bv.view_type} and respond ONLY with a function name in this EXACT format: llm_purpose_pct where pct is your confidence from 0-100. Examples: llm_bubble_sort_100, llm_aes_cbc_decrypt_85, llm_malloc_90. You MUST include the confidence number. NO OTHER TEXT! DO NOT EXPLAIN REASONING!",
                    messages=[
                        {
                            "role": "user",
                            "content": code
                        }
                    ]
                )
                
                if message.content:
                    content = message.content[0].text
                    new_name = self.extract_llm_pattern(content)
                    results[func] = new_name
                    if new_name:
                        log_info(f"Named function {func.name} -> {new_name}")
                else:
                    results[func] = None
                    
            except Exception as e:
                log_info(f"Error processing function {func.name}: {str(e)}")
                results[func] = None
        
        return results

    def process_batch_api(self, client, functions):
        """Process functions using batch API"""
        if not functions:
            return {}

        # Create batch requests
        batch_requests = []
        function_map = {}  # Map request IDs to functions
        
        for func in functions:
            request_id = str(uuid.uuid4())
            function_map[request_id] = func
            
            func_prototype = "".join(str(t) for t in func.type_tokens)
            pseudo_c = func.pseudo_c
            lines = pseudo_c.get_linear_lines(func.hlil.root)
            func_body = "\n".join(str(line) for line in lines)
            code = func_prototype + "\n" + func_body
            
            batch_requests.append({
                "custom_id": request_id,
                "params": {
                    "model": "claude-sonnet-4-20250514",  
                    "max_tokens": 50,
                    "temperature": 0,  # Deterministic output
                    "system": f"Analyze the decompiled function from a {self.bv.platform} {self.bv.view_type} and respond ONLY with a function name in this EXACT format: llm_purpose_pct where pct is your confidence from 0-100. Examples: llm_bubble_sort_100, llm_aes_cbc_decrypt_85, llm_malloc_90. You MUST include the confidence number. NO OTHER TEXT! DO NOT EXPLAIN REASONING!",
                    "messages": [
                        {
                            "role": "user",
                            "content": code
                        }
                    ]
                }
            })

        # Submit batch job
        try:
            log_info(f"Submitting batch of {len(batch_requests)} functions...")
            
            batch_response = client.beta.messages.batches.create(
                requests=batch_requests
            )
            
            batch_id = batch_response.id
            log_info(f"Batch submitted with ID: {batch_id}")
            
            # Wait for batch completion
            while True:
                batch_status = client.beta.messages.batches.retrieve(batch_id)
                
                if batch_status.processing_status == "ended":
                    log_info(f"Batch status: {batch_status.processing_status}")
                    log_info("Processing batch results...")
                    break
                elif batch_status.processing_status in ["failed", "expired", "canceled"]:
                    log_info(f"Batch processing failed: {batch_status.processing_status}")
                    return {}
                
                time.sleep(5)  # Check every 5 seconds
            
            # Retrieve results from the results_url
            results = {}
            if hasattr(batch_status, 'results_url') and batch_status.results_url:
                
                # Get results from the URL
                response = requests.get(
                    batch_status.results_url,
                    headers={
                        'x-api-key': Settings().get_string("ClaNaFu.api_key"),
                        'anthropic-version': '2023-06-01'
                    }
                )
                
                if response.status_code == 200:
                    # Parse JSONL results
                    new_results = False
                    for line in response.text.strip().split('\n'):
                        if line.strip():
                            result = json.loads(line)
                            custom_id = result.get('custom_id')
                            if custom_id in function_map:
                                # Check if result succeeded and has message content
                                if (result.get('result') and 
                                    result['result'].get('type') == 'succeeded' and  # Changed from 'message' to 'succeeded'
                                    result['result'].get('message') and
                                    result['result']['message'].get('content')):
                                    content = result['result']['message']['content'][0]['text']
                                    new_name = self.extract_llm_pattern(content)
                                    results[function_map[custom_id]] = new_name
                                    new_results = True
                                else:
                                    results[function_map[custom_id]] = None
                    if new_results:
                        self.bv.update_analysis()
                    else:
                        log_info("No valid results found in batch response")
                        log_info(response.text)
                else:
                    log_info(f"Failed to retrieve batch results: {response.status_code}")
                    return {}
            else:
                log_info("No results_url found in batch response")
                return {}
            
            return results
            
        except Exception as e:
            log_info(f"Batch processing error: {str(e)}")
            # Fallback to normal API processing
            return self.process_normal_api(client, functions)

    def extract_llm_pattern(self, text):
        """Extract function name from Claude's response"""
        # Clean up the text first
        text = text.strip()
        
        # Look for the pattern at the beginning or end of the response
        patterns = [
            r'llm_[a-zA-Z0-9_]+_\d{1,3}',  # Standard pattern
            r'llm_[a-zA-Z0-9_]+',          # Pattern without confidence
        ]
        
        match = re.search(patterns[0], text)
        if match:
            return match.group()
        else:
            print("WARNING: Claude did not return a valid function name in the expected format.")
            match = re.search(patterns[1], text)
            if match:
                return match.group()
            else:
                print("WARNING: Claude did not return a valid function name at all!")
                print(f"Got text: {text}")
        
        return None

    def find_strongly_connected_components(self):
        """Find strongly connected components in the call graph using Tarjan's algorithm"""
        index_counter = [0]
        stack = []
        lowlinks = {}
        index = {}
        on_stack = {}
        sccs = []
        
        def strongconnect(v):
            index[v] = index_counter[0]
            lowlinks[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack[v] = True
            
            for w in call_graph[v]:
                if w not in index:
                    strongconnect(w)
                    lowlinks[v] = min(lowlinks[v], lowlinks[w])
                elif on_stack[w]:
                    lowlinks[v] = min(lowlinks[v], index[w])
            
            if lowlinks[v] == index[v]:
                component = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    component.append(w)
                    if w == v:
                        break
                sccs.append(component)
        
        for v in call_graph:
            if v not in index:
                strongconnect(v)
        
        return sccs

def call_start_analysis(bv):
    analysis = ClaudeNameAllFunctions(bv)
    analysis.start() 

PluginCommand.register(
    "analyze functions",
    "analyzes each function from leaves up",
    call_start_analysis
)

Settings().register_group("llm_name_functions", "Get Claude to name functions for you")
Settings().register_setting(
    "ClaNaFu.api_key",
    """
    {
        "title" : "Claude API Key",
        "type" : "string",
        "default" : "",
        "description" : "You need an API key to get Claude to do your bidding.",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }"""
)
Settings().register_setting(
    "ClaNaFu.use_batch_mode",
    """
    {
        "title" : "Use Batch API Mode",
        "type" : "boolean",
        "default" : false,
        "description" : "Use batch API for cost savings (slower) or normal API for speed. Batch mode is cheaper but can take a long time, while normal mode is faster but costs more.",
        "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
    }"""
)
