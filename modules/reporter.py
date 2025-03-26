import json
from colorama import Fore

def generate_report(results, output_file):
    if output_file.endswith('.json'):
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
    elif output_file.endswith('.txt'):
        with open(output_file, 'w') as f:
            f.write("WebScanner Report\n")
            f.write("=================\n\n")
            
            f.write("Vulnerabilities:\n")
            for vuln in results["vulnerabilities"]:
                f.write(f"- Type: {vuln['type']} ({vuln['severity']})\n")
                f.write(f"  URL: {vuln['endpoint']}\n")
                f.write(f"  Payload: {vuln['payload']}\n\n")
            
            f.write("Hidden Files:\n")
            for hidden in results["hidden_files"]:
                f.write(f"- {hidden}\n")
            
            f.write("\nInternal Links:\n")
            for link in results["internal_links"]:
                f.write(f"- {link}\n")
    
    print(f"{Fore.GREEN}[+] Report saved to {output_file}")
