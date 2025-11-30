import time
import sys
from cosdata import Client
from sentence_transformers import SentenceTransformer

# --- COLORS FOR TERMINAL ---
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# --- CONFIGURATION ---
ADMIN_KEY = "admin123"
HOST_URL = "http://localhost:8443"
COLLECTION_NAME = "cyber_threats_v2" # Matches your ingest script

def print_bar(score):
    """Creates a visual confidence bar [██████----]"""
    filled = int(score * 20)
    bar = "█" * filled + "-" * (20 - filled)
    color = RED if score > 0.6 else YELLOW
    return f"{color}[{bar}] {int(score*100)}%{RESET}"

def log_incident(text, threat):
    """Saves alerts to a file for 'Audit' demo"""
    with open("incidents.log", "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] ALERT: {threat} | Raw: {text}\n")

def main():
    print(f"\n{CYAN}🛡️  CYBER_GUARDIAN SOC CONSOLE v4.0{RESET}")
    print("---------------------------------------")
    
    print("⏳ Loading Neural Engine...", end="\r")
    model = SentenceTransformer('all-MiniLM-L6-v2')
    print(f"{GREEN}✓ Neural Engine Loaded     {RESET}")

    print("🔌 Connecting to Vector DB...", end="\r")
    client = Client(host=HOST_URL, username="admin", password=ADMIN_KEY, verify=False)
    collection = client.get_collection(COLLECTION_NAME)
    print(f"{GREEN}✓ Cosdata DB Connected     {RESET}\n")

    print(f"{YELLOW}System Ready. Listening for logs... (Type 'exit' to quit){RESET}")

    while True:
        try:
            # Simulate a Linux Terminal Prompt
            query = input(f"\n{CYAN}analyst@soc-terminal:~$ {RESET}")
            
            if query.lower() == "exit": 
                print("Shutting down..."); break
            if query.strip() == "": continue
            
            # Fake processing time for effect
            print("🔍 Analyzing vector embeddings...", end="\r")
            time.sleep(0.3)

            # 1. Search
            vector = model.encode(query).tolist()
            res = collection.search.dense(query_vector=vector, top_k=1, return_raw_text=True)

            # 2. Result Logic
            if res and 'results' in res and len(res['results']) > 0:
                match = res['results'][0]
                score = match['score']
                
                # Extract Metadata (Universal Finder)
                meta = match.get('metadata', {})
                # If metadata is missing, try payload
                if not meta: meta = match.get('payload', {})
                
                if score > 0.50:
                    # --- CRITICAL THREAT UI ---
                    threat = meta.get('category') or meta.get('text') or "Unknown Threat"
                    tech = meta.get('technique', 'T????')
                    
                    print(f"\n{RED}🚨 CRITICAL ALERT DETECTED{RESET}")
                    print("----------------------------")
                    print(f"Confidence: {print_bar(score)}")
                    print(f"Technique:  {tech}")
                    print(f"Category:   {threat}")
                    print(f"Action:     {meta.get('fix')}")
                    
                    # Show SOC Commands if available
                    if 'commands' in meta:
                        print(f"\n{YELLOW}>> EXECUTE RESPONSE PROTOCOLS:{RESET}")
                        for cmd in meta['commands']:
                            print(f"   $ {cmd}")
                    
                    # Log to file
                    log_incident(query, threat)
                    print(f"\n{CYAN}[+] Incident logged to incidents.log{RESET}")
                else:
                    # --- SAFE UI ---
                    print(f"\n{GREEN}✅ System Clean{RESET}")
                    print(f"Analysis: Low similarity match ({int(score*100)}%). No action needed.")

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")

if __name__ == "__main__":
    main()