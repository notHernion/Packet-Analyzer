#!/bin/bash

set -uo pipefail
# Import the TCPdump Functions library 
source "/home/$USER/Final-Project/tcp_functions.sh"

# Main menu function
main_menu() {
    HOST_IP=$(hostname -I)
    DefaultGateway_IP=$(route -n | grep 'UG[ \t]' | awk '{print $2}')
    echo "======================================================================="
    printf "Host IP: %s\t\t DefaultGateway IP: %s\n" $HOST_IP $DefaultGateway_IP
    echo "======================================================================="
    echo "Welcome to My TCP Dump Software"
    echo "1. Start Capture"
    echo "2. Display Captured Traffic"
    echo "3. Log User Login Information"
    echo "4. How may users are using specific port"
    echo "5. Filter Traffic"
    echo "6. Number of Online Users"
    echo "7. Filter Source IP"
    echo "8. Backup PCAP files"
    echo "9. Exit"
    echo "======================================================================="
    read -p "Please enter your choice: " choice

    case $choice in
        1) capture_traffic ;;
        2) display_traffic ;;
        3) log_user_login ;;
        4) users_per_port ;;
        5) filter_traffic ;;
        6) online_users ;;
        7) filter_ip ;;
        8) backup_pcap_files ;;
        9) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice. Please enter a valid option." ;;
    esac
}

# Main function
main() {
    while true; do
        main_menu
        read -p "Press any Key To continue"
        clear
    done
}

# Call the main function
main
