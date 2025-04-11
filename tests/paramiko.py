import paramiko
import getpass

def ssh_connect(hostname, username, password=None):
    # Create SSH client
    client = paramiko.SSHClient()
    
    # Automatically add the server's host key
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # Connect to the server
        if password is None:
            password = getpass.getpass(f"Enter password for {username}@{hostname}: ")
        
        client.connect(hostname, username=username, password=password)
        print(f"Successfully connected to {hostname}")
        
        # Execute a simple command
        stdin, stdout, stderr = client.exec_command('uname -a')
        print("\nSystem information:")
        print(stdout.read().decode())
        
    except paramiko.AuthenticationException:
        print("Authentication failed, please verify your credentials")
    except paramiko.SSHException as ssh_exception:
        print(f"SSH connection failed: {ssh_exception}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the connection
        client.close()

if __name__ == "__main__":
    # Example usage
    host = input("Enter hostname: ")
    user = input("Enter username: ")
    ssh_connect(host, user)