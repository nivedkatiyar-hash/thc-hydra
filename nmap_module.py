import re

def weave_output_to_input(input_log, output_targets):
    """
    Parses a Hydra result file (-o) and extracts host/port
    to create a clean target list (-M) for the next cycle.
    """
    try:
        with open(input_log, 'r') as log_file, open(output_targets, 'w') as target_file:
            for line in log_file:
                # Hydra standard output: [host] [port] [service] [login]:[password]
                # Regex to isolate the host and port
                match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]\s+\[(\d+)\]', line)
                if match:
                    host, port = match.groups()
                    target_file.write(f"{host}:{port}\n")
        print(f"[+] Reconstruction complete. {output_targets} is ready for the Hydra.")
    except Exception as e:
        print(f"[!] The weave faltered: {e}")

#this was made by a AI ( shoutout l0gicx ) I think it is probably broken can y'all fix it plz
