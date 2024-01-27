from cryptography import x509
import socket
import ssl
import csv

# Read hostnames from the 'hostnames.txt' file
with open('hostnames.txt') as hostnames_file:
    hostnames = hostnames_file.read().splitlines()

csv_columns = ["Domain", "TLS Version", "Expiry Date"]

# Create default SSL context
context = ssl.create_default_context()
# Override context to handle expired certificates
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

# Open CSV file in write mode
with open("certFiles.csv", "w", newline="") as filecsv:
    writer = csv.DictWriter(filecsv, fieldnames=csv_columns)
    writer.writeheader()

    # Iterate over each hostname
    for hostname in hostnames:
        try:
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate in DER format
                    data = ssock.getpeercert(True)

                    # Convert cert to PEM format
                    pem_data = ssl.DER_cert_to_PEM_cert(data)

                    # Extract cert info from PEM format
                    cert_data = x509.load_pem_x509_certificate(str.encode(pem_data))

                    # Write certificate information to CSV
                    writer.writerow({
                        "Domain": hostname,
                        "TLS Version": ssock.version(),
                        "Expiry Date": cert_data.not_valid_after,
                    })

        except Exception as e:
            print(f"Error checking certificate for {hostname}: {e}")

print("Certificate information written to certFiles.csv")
