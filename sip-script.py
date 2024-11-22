import pyshark
import os
import sys
from datetime import datetime
import glob

def extract_sip_info(file_path, output_file):
    try:
        # Create capture object for SIP packets
        capture = pyshark.FileCapture(
            file_path,
            display_filter='sip',
            keep_packets=False,
            output_file=None
        )
        
        capture.set_debug()
        print(f"Processing SIP messages in '{file_path}'...")
        
        # First pass to count messages
        total_packets = 0
        register_count = 0
        invite_count = 0
        
        # Temporary file for storing message details
        temp_file = output_file + '.temp'
        
        # Process packets and write to temporary file
        with open(temp_file, 'w') as file:
            file.write("Detailed SIP Message Information:\n")
            file.write("=" * 50 + "\n")
            
            for packet in capture:
                try:
                    total_packets += 1
                    print(f"Processing packet {total_packets}...")
                    
                    if 'SIP' in packet:
                        # Check for REGISTER or INVITE messages
                        message_type = None
                        if hasattr(packet.sip, 'request_method'):
                            if packet.sip.request_method == "REGISTER":
                                message_type = "REGISTER"
                                register_count += 1
                            elif packet.sip.request_method == "INVITE":
                                message_type = "INVITE"
                                invite_count += 1
                        elif hasattr(packet.sip, 'request_line'):
                            if "REGISTER" in packet.sip.request_line:
                                message_type = "REGISTER"
                                register_count += 1
                            elif "INVITE" in packet.sip.request_line:
                                message_type = "INVITE"
                                invite_count += 1
                        
                        if message_type:
                            print(f"Found {message_type} message!")
                            sip_headers = packet.sip
                            
                            # Write message type and timestamp
                            timestamp = packet.sniff_time.strftime('%Y-%m-%d %H:%M:%S.%f')
                            file.write(f"\nMessage Type: {message_type}\n")
                            file.write(f"Timestamp: {timestamp}\n")
                            
                            # Extract To header
                            if hasattr(sip_headers, 'to'):
                                to_header = sip_headers.to
                                file.write(f"To: {to_header}\n")
                                if ';' in to_header:
                                    file.write("To Header Parameters:\n")
                                    params = to_header.split(';')[1:]
                                    for param in params:
                                        param = param.strip()
                                        if '=' in param:
                                            key, value = param.split('=', 1)
                                            file.write(f"  {key.strip()}: {value.strip()}\n")
                                        else:
                                            file.write(f"  {param}\n")
                            
                            # Extract From header
                            if hasattr(sip_headers, 'from_'):
                                from_header = sip_headers.from_
                                file.write(f"From: {from_header}\n")
                                if ';' in from_header:
                                    file.write("From Header Parameters:\n")
                                    params = from_header.split(';')[1:]
                                    for param in params:
                                        param = param.strip()
                                        if '=' in param:
                                            key, value = param.split('=', 1)
                                            file.write(f"  {key.strip()}: {value.strip()}\n")
                                        else:
                                            file.write(f"  {param}\n")

                            # Extract P-Access-Network-Info
                            if hasattr(sip_headers, 'p_access_network_info'):
                                p_access_network_info = sip_headers.p_access_network_info
                                file.write(f"P-Access-Network-Info: {p_access_network_info}\n")
                                file.write("P-Access-Network-Info Parameters:\n")
                                for param in p_access_network_info.split(";"):
                                    param = param.strip()
                                    if '=' in param:
                                        key, value = param.split('=', 1)
                                        file.write(f"  {key.strip()}: {value.strip()}\n")
                                    else:
                                        file.write(f"  {param}\n")
                            
                            # Extract Cellular-Network-Info
                            if hasattr(sip_headers, 'cellular_network_info'):
                                cellular_network_info = sip_headers.cellular_network_info
                                file.write(f"Cellular-Network-Info: {cellular_network_info}\n")
                                file.write("Cellular-Network-Info Parameters:\n")
                                for param in cellular_network_info.split(";"):
                                    param = param.strip()
                                    if '=' in param:
                                        key, value = param.split('=', 1)
                                        file.write(f"  {key.strip()}: {value.strip()}\n")
                                    else:
                                        file.write(f"  {param}\n")
                            
                            file.write("-" * 50 + "\n")

                except AttributeError as e:
                    print(f"Skipping packet due to missing attribute: {str(e)}")
                    continue
                except Exception as e:
                    print(f"Error processing packet: {str(e)}")
                    continue

        # Write final file with summary at top
        with open(output_file, 'w') as final_file:
            # Write summary
            final_file.write("SIP Analysis Summary\n")
            final_file.write("=" * 50 + "\n")
            final_file.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            final_file.write(f"Input File: {os.path.basename(file_path)}\n")
            final_file.write(f"Total SIP Packets: {total_packets}\n")
            final_file.write(f"REGISTER Messages: {register_count}\n")
            final_file.write(f"INVITE Messages: {invite_count}\n")
            final_file.write("=" * 50 + "\n\n")
            
            # Copy content from temporary file
            with open(temp_file, 'r') as temp:
                final_file.write(temp.read())
        
        # Remove temporary file
        os.remove(temp_file)

        print(f"\nSummary:")
        print(f"Total packets processed: {total_packets}")
        print(f"REGISTER messages found: {register_count}")
        print(f"INVITE messages found: {invite_count}")

    except pyshark.capture.capture.TSharkCrashException as e:
        print(f"TShark crashed: {str(e)}")
        print("Please ensure you have the latest version of TShark installed")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        sys.exit(1)
    finally:
        try:
            capture.close()
        except:
            pass

def main():
    # Create output directory if it doesn't exist
    output_dir = 'output'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Get all pcap files from traces directory
    traces_dir = 'traces'
    if not os.path.exists(traces_dir):
        print(f"Error: Traces directory '{traces_dir}' not found!")
        sys.exit(1)

    pcap_files = glob.glob(os.path.join(traces_dir, '*.pcap'))
    if not pcap_files:
        print(f"Error: No .pcap files found in '{traces_dir}'!")
        sys.exit(1)

    # Process each pcap file
    for pcap_file in pcap_files:
        # Generate output filename
        base_name = os.path.basename(pcap_file)
        output_file = os.path.join(output_dir, base_name.replace('.pcap', '.txt'))
        
        print(f"\nProcessing: {base_name}")
        extract_sip_info(pcap_file, output_file)
        print(f"Results saved in '{output_file}'")

    print("\nAll files processed successfully!")

if __name__ == "__main__":
    main()
