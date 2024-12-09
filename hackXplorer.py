import ipaddress
import sys
import pyfiglet
import socket
import subprocess
import re
import os
import stat
import json
import requests
from requests.exceptions import SSLError, RequestException

##### FLOW
# 1. Introduction
# 2. Getting IP and validating it
# 3. Nmap Scan
# 4. Show open ports and what do you recommend for each service
# 5. Suggest additional exploitations according to most common vulnerabilities...?
# 6. Generate final report based on findings

## Step 1: Introduction (Intro message + permission)
def introduction():
    # Title
    print("-----------------------------------------------------------")
    print("\033[36m" + pyfiglet.figlet_format("HackXplorer") + "\033[0m")
    print("-----------------------------------------------------------")

    # Intro
    print("Welcome to HackXplorer, an interactive web app pentest tool.")
    print("----------------------------------------------------------")

    # Warning for permissions
    print("\033[91m" + "WARNING: Make sure you have permission to pentest the IP you are targeting!" + "\033[0m")
    while True:
        user_permission = input("Do you have permission to proceed? (yes/no): ").lower().strip()
        if user_permission == 'yes':
            break
        elif user_permission == 'no':
            print("Exiting... No unethical hacking allowed here ¯\\_(ツ)_/¯ ")
            sys.exit(0)
        else:
            print("Please answer 'yes' or 'no'.")

## Step 2: Getting IP 
def get_IP():
    print("----------------------------------------------------------")
    while True:
        user_input = input("### Enter the target IP address or domain name:  \n(or type QUIT to exit): ")
        
        if user_input.lower() == 'quit':
            print("Exiting HackXplore... Goodbye!")
            sys.exit(0)
    
        try:
            # Check if the input is a valid IP address
            ipaddress.ip_address(user_input)
            return user_input
        except ValueError:
            # If not a valid IP address, attempt to resolve it as a domain name
            try:
                target_ip = socket.gethostbyname(user_input)
                print(f"Resolved {user_input} to IP address: {target_ip}")
                return target_ip
            except socket.gaierror:
                print(f"ERROR! The domain name '{user_input}' could not be resolved. Please try again.")

# Step 3: Nmap Scan (shows open ports and their services)
def nmap_scan(target_ip):
    # Check if a previous scan exists
    db_filename = f"{target_ip}nmap.txt"
    if os.path.exists(db_filename):
        print(f"Previous scan found for {target_ip}. Loading results from file...")
        with open(db_filename, 'r') as file:
            nmap_output = file.read().strip()
        if nmap_output:
            print("Nmap Scan Results:")
            print(nmap_output)
            open_ports = parse_nmap_output(nmap_output)
            return open_ports
        else:
            print("No data found in the previous scan file. Proceeding with a new scan...")

    print(f"Performing Nmap scan for {target_ip} ...")
    print("----------------------------------------------------------")
    try:
        # Run Nmap as a subprocess with -T4 and -sV
        result = subprocess.run(['nmap', '-T4', '-sV', target_ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Check if the command was successful
        if result.returncode == 0:
            nmap_output = result.stdout.strip()
            print("Nmap Scan Results:")
            print(nmap_output)
            # Save results to a file
            with open(db_filename, 'w') as file:
                file.write(nmap_output)
            # Parse the output to extract open ports and services
            open_ports = parse_nmap_output(nmap_output)
            return open_ports
        else:
            print("Nmap encountered an error:")
            print(result.stderr)
            return []
    except FileNotFoundError:
        print("Nmap is not installed or not found in your PATH.")
        sys.exit(1)

def parse_nmap_output(nmap_output):
    open_ports = []
    # Regular expression to match open ports and services
    # Example line: "80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))"
    port_regex = re.compile(r"^(\d+)/tcp\s+open\s+([\w\-/]+)\s*(.*)", re.IGNORECASE)
    lines = nmap_output.splitlines()
    for line in lines:
        match = port_regex.match(line)
        if match:
            port = int(match.group(1))
            service = match.group(2)
            version_info = match.group(3).strip()
            open_ports.append({'port': port, 'service': service, 'version_info': version_info})
    return open_ports
def ssl_scan(target_ip, port):
    print(f"\nRunning SSL Vulnerability Scan on {target_ip}:{port}...")
    print("----------------------------------------------------------")
    
    try:
        # Path to testssl.sh script
        testssl_path = os.path.join(os.getcwd(), 'venv', 'testssl.sh', 'testssl.sh')
        
        # Define the output filename
        output_filename = f"{target_ip}_{port}sslscan.txt"
        print(f"SSL Scan results for {target_ip}:{port}:")

        # Check if a previous scan exists
        if os.path.exists(output_filename):
            print(f"Previous scan found for {target_ip}:{port}. Loading results from file...")
            with open(output_filename, 'r') as file:
                content = file.read()
                print(content)
        else:
            print(f"No previous scan found for {target_ip}:{port}. Running a new scan...")
            
            # Run the script with the --logfile option
            process = subprocess.Popen(
                ['bash', testssl_path, '-U', f'{target_ip}:{port}'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Open the output file in append mode
            with open(output_filename, 'w') as file:
                # Read the output line by line
                for line in iter(process.stdout.readline, ''):
                    print(line, end='')  # Print each line to the console
                    file.write(line)    # Write each line to the file
                
                # Read and print errors, if any
                for line in iter(process.stderr.readline, ''):
                    print(line, end='')  # Print error lines to the console
                    file.write(line)    # Write error lines to the file
            
            # Wait for the process to complete
            process.wait()
            
            if process.returncode != 0:
                print(f"\nSSL scan finished with errors (exit code {process.returncode}).")
            else:
                print(f"\nSSL scan completed successfully. Results saved to {output_filename}.")
    
    except FileNotFoundError:
        print("testssl.sh command not found in the specified path.")
    except PermissionError:
        print("Permission denied: Unable to execute testssl.sh. Please check the script permissions.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")



def find_hidden_pages(target_ip):
    print(f"\nRunning Gobuster to find hidden pages on {target_ip}...")
    print("----------------------------------------------------------")
    
    try:
        # Construct the target URL
        url = f'http://{target_ip}'  # Ensure correct protocol (http/https)

        # Resolve the absolute path to the wordlist
        wordlist_path = os.path.join(os.getcwd(), 'venv', 'SecLists', 'Discovery', 'Web-Content', 'directory-list-2.3-small.txt')

        # Check if the wordlist exists
        if not os.path.exists(wordlist_path):
            print(f"Error: Wordlist not found at {wordlist_path}")
            return

        # Define the output filename based on the target IP and port
        output_filename = f"{target_ip}_gobuster.txt"

        # Check if the previous scan results already exist
        if os.path.exists(output_filename):
            print(f"Previous Gobuster scan found for {target_ip}. Loading results from file...")
            with open(output_filename, 'r') as file:
                content = file.read()
                print(content)  # Print out the previous scan results
        else:
            print(f"No previous scan found for {target_ip}. Running a new scan...")

            # Path to Gobuster
            gobuster_path = 'gobuster'  # Update with full path if needed

            # Run Gobuster and stream output
            process = subprocess.Popen(
                [gobuster_path, 'dir', '-u', url, '-w', wordlist_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Open the output file in write mode to save results
            with open(output_filename, 'w') as file:
                for line in iter(process.stdout.readline, ''):
                    print(line, end='')  # Print each line to the console
                    file.write(line)    # Write each line to the file
                
                # Read and print errors, if any
                for line in iter(process.stderr.readline, ''):
                    print(line, end='')  # Print error lines to the console
                    file.write(line)    # Write error lines to the file

            # Wait for the process to complete
            process.wait()

            if process.returncode != 0:
                print(f"\nGobuster scan finished with errors (exit code {process.returncode}).")
            else:
                print(f"\nGobuster scan completed successfully. Results saved to {output_filename}.")

    except FileNotFoundError:
        print("Gobuster is not installed or not found in your PATH.")
    except Exception as e:
        print(f"An error occurred while running Gobuster: {str(e)}")

import requests
import requests

import requests

def brute_force_login(ip, full_url):
    # Hardcoded file paths for the username and password lists
    username_file = "venv/SecLists/Usernames/top-usernames-shortlist.txt"
    password_file = "venv/SecLists/Passwords/Common-Credentials/top-passwords-shortlist.txt"

    print(f"Target URL: {full_url}")

    try:
        # Load usernames and passwords
        with open(username_file, 'r') as u_file, open(password_file, 'r') as p_file:
            usernames = [line.strip() for line in u_file]
            passwords = [line.strip() for line in p_file]

        # Brute-force attempt
        for username in usernames:
            print(f"Trying username: {username}")
            
            for password in passwords:
                #print(f"Trying password: {password}")
                
                # Prepare the POST payload
                payload = {
                    'user_login': username,
                    'user_password': password
                }

                # Send POST request
                try:
                    response = requests.post(full_url, data=payload, allow_redirects=True)
                    # If the final URL isn't the failure URL, assume success
                    if response.status_code != 200:
                        print(f"Success! Username: {username}, Password: {password}")
                        return True

                except SSLError as ssl_err:
                    # Specifically catch SSL handshake failure and other SSL issues
                    print(f"Success! Username: {username}, Password: {password}")
                    with open(f"{ip}_bruteforce.txt", "a") as file:
                        file.write(f"Username: {username}, Password: {password}\n")
                    return True

        print("Brute-force failed. No valid credentials found.")
        return False

  
    except FileNotFoundError as e:
        print(f"File not found: {e}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def generate_report(ip_address):
    # Directory where the files are stored
    output_directory = os.getcwd()  # Current working directory
    # Define the report file name
    report_filename = f"{ip_address}_final_report.txt"

    # Open the report file in write mode
    with open(report_filename, "w") as report_file:
        # Write a header to the report
        report_file.write(f"Final Report for IP: {ip_address}\n")
        report_file.write("=" * 50 + "\n\n")

        # Initialize a list to store the filenames to combine
        files_to_combine = []

        # Search for all files that contain the target IP in their name
        for filename in os.listdir(output_directory):
            # Collect files that match the pattern (e.g., *{ip_address}_bruteforce.txt* or others)
            if filename.startswith(f"{ip_address}") :
                files_to_combine.append(filename)

        if files_to_combine:
            # Loop through all the files found
            for filename in files_to_combine:
                try:
                    # Open each individual file and read its contents
                    with open(filename, "r") as file:
                        report_file.write(f"Contents from file: {filename}\n")
                        report_file.write("-" * 50 + "\n")
                        report_file.write(file.read())  # Append file content to report
                        report_file.write("\n\n")  # Add a new line for separation
                except Exception as e:
                    print(f"Error reading {filename}: {e}")
        else:
            report_file.write("No relevant scan files found for this target.\n")

    print(f"Report generated: {report_filename}")


def select_service_to_test(open_ports, target_ip):
    # Process the open_ports to find services that HackXplorer can test (HTTP, SSL)
    print("\nHere are the services recognized that HackXplorer has identified:")
    for port_info in open_ports:
        port = port_info['port']
        service = port_info['service']
        version_info = port_info['version_info']
        print(f"Port {port}: {service} ({version_info})")

    

    while True:
        print("\nSuggested actions based on the open ports:")
        print("1. SSL Vulnerability Scan")
        print("2. Find Hidden Pages")
        print("3. Brute Force a login page")
        print("4. Generate a report")
        print("5. Exit")
        choice = input("Enter the number of your choice: ").strip()
        if choice == '1':
            # Run SSL Vulnerability Scan
            ssl_ports = [port_info['port'] for port_info in open_ports if 'ssl' in port_info['service'].lower() or 'https' in port_info['service'].lower()]
            if ssl_ports:
                for port in ssl_ports:
                    ssl_scan(target_ip, port)
            else:
                print("No SSL services detected on open ports.")
        elif choice == '2':
            # Run Gobuster to find hidden pages
            http_ports = [port_info['port'] for port_info in open_ports if 'http' in port_info['service'].lower() or port_info['port'] in [80, 8080]]
            if http_ports:
                find_hidden_pages(target_ip)
            else:
                print("No HTTP services detected on open ports.")
        elif choice == '3':
            # Run Brute Force (Placeholder)
            print("Brute force functionality is not yet implemented.")
            # You can implement your brute force function here
            login_url = input("Please give the url to the login page:")
            brute_force_login(target_ip, login_url)
        elif choice == '4':
            # Go back to IP input
            generate_report(target_ip)
        elif choice == '5':
            # Exit the program
            print("Exiting HackXplorer... Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice. Try again.")

####### MAIN FUNCTION #######

if __name__ == "__main__":
    introduction()

    while True:
        target_ip = get_IP()
        print(f"Great! Now scanning {target_ip} ...")
        open_ports = nmap_scan(target_ip)
        if open_ports:
            select_service_to_test(open_ports, target_ip)
        else:
            print("No open ports found or unable to parse Nmap output.")