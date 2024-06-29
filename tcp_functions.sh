#!/bin/bash

# function to capture network traffic using tcpdump
capture_traffic() {
 trap 'echo "Capture interrupted. Returning to main menu..."; return' SIGINT
    DATE=$(date +%y-%m-%d-%h:%m:%s)
    echo "starting network capture..."
    sudo tcpdump -w - | tee captured_traffic_$DATE.pcap | tcpdump -r -

    if ! [[ $? -eq 0 ]]; then 
      echo "error:$0:$LINENO: something went wrong."
      exit 1
    fi 
    trap - SIGINT
    return 0
}
# function to display captured traffic
display_traffic() {
    trap 'echo "Display interrupted. Returning to main menu..."; return' SIGINT
    clear
    ls -1 *.pcap | awk '{printf "%d- %s\n", NR, $1}'
    read -p "Enter the number of the file to display: " FILENAME
    SELECTED_FILE=$(ls -1 *.pcap | awk -v num=$FILENAME 'NR==num {print $1}')
    if [[ -z $SELECTED_FILE ]]; then
        echo "Invalid file number. Please try again."
        return 1
    fi
    echo "Displaying captured traffic..."
    sudo tcpdump -r $SELECTED_FILE 2> /dev/null
    if [[ $? -gt 1 ]]; then 
        echo "Error: $0:$LINENO: Something went wrong."
        return 1
    fi 
    trap - SIGINT
    return 0
}
# Function to log user login information
log_user_login() {
  echo "Logging user login information..."
  LOG_FILE="user_login_log.txt"

  # Check if journalctl is available
  if ! command -v journalctl &> /dev/null; then
    echo "Error: journalctl is not available on this system."
    exit 1
  fi

  # Log user login information
  if [[ -f $LOG_FILE ]]; then
    sudo journalctl --since "yesterday" --output cat | grep -i 'session opened' >> $LOG_FILE
  else
    sudo journalctl --since "yesterday" --output cat | grep -i 'session opened' > $LOG_FILE
  fi

  if ! [[ $? -eq 0 ]]; then 
    echo "Error:$0:$LINENO: Something went wrong."
    exit 1
  fi
}
# The number of users that used a certain port(s), for example 80 and 8080
users_per_port() {
  echo "counting the number of users that used a certain port(s)..."
  read -p "Enter the port number(s) separated by a space: " PORTS
  PORTS_PATTERN='^[0-9]{1,5}$'

  for PORT in $PORTS; do
    if ! [[ $PORT =~ $PORTS_PATTERN ]]; then
      echo "Error:$0:$LINENO: Invalid PORT NUMBER"
      exit 1
    fi 
    echo "Port $PORT was used by $(sudo netstat -tuln | grep $PORT | wc -l) user(s)"
  done
}

# filter incoming and outgoing traffic
filter_traffic() {
  echo "filtering incoming and outgoing traffic..."
  read -p "Enter the IP address to filter: " IP

  IP_PATTERN='^([0-9]{1,3}\.){3}([0-9]{1,3})$'
  if ! [[ $IP =~ $IP_PATTERN ]]; then
    echo "Error:$0:$LINENO: Invalid IP"
    exit 1
  fi 

  DATE=$(date +%y-%m-%d-%h:%m:%s)

  trap 'echo "Display interrupted. Returning to main menu..."; return' SIGINT
  sudo tcpdump -i any -vv -w - src $IP or dst $IP | tee $IP-CapturedPackets-$DATE.pcap | tcpdump -r -

  if ! [[ $? -eq 0 ]]; then 
      echo "error:$0:$LINENO: something went wrong."
      exit 1
    fi
  
  trap - SIGINT
  return 0
}

#  the number of online users from-to a specific time
online_users() {
  echo "counting the number of online users from-to a specific time..."
  INPUT_PATTERN='^[0-9]{1,2}:[0-9]{1,2}$'
  read -p "Enter the start time (format: HH:MM): " START_TIME
  if ! [[ $START_TIME =~ $INPUT_PATTERN ]]; then
  	echo "Error:$0:$LINENO: Invalid Input"
  exit 1
  fi
  read -p "Enter the end time (format: HH:MM): " END_TIME
  if ! [[ $END_TIME =~ $INPUT_PATTERN ]]; then
  	echo "Error:$0:$LINENO: Invalid Input"
  exit 1
  fi
  echo "The number of online users from $START_TIME to $END_TIME is $(who | awk -v start=$START_TIME -v end=$END_TIME '$4 >= start && $4 <= end' | wc -l)"
}

# Filter based on a specific ip address that isn't supposed to visit the web browser 
filter_ip() {
  echo "Filtering based on a specific IP address that isn't supposed to visit the web browser..."
  read -p "Enter the IP address to filter: " IP
  IP_PATTERN='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  if ! [[ $IP =~ $IP_PATTERN ]]; then
    echo "Error:$0:$LINENO: Invalid IP address"
    exit 1
  fi

  DATE=$(date +%y-%m-%d-%h:%m:%s)

  trap 'echo "Capture interrupted. Returning to main menu..."; return' SIGINT
  sudo tcpdump -i any -vv -w - "src $IP and (dst port 80 or dst port 443)" | tee $IP-SpecificCapture-$DATE.pcap| tcpdump -r - 
  if ! [[ $? -eq 0 ]]; then 
    echo "Error:$0:$LINENO: Something went wrong."
    exit 1
  fi
  trap - SIGINT
  return 0
}

backup_pcap_files() {
  DATE=$(date +%y-%m-%d-%H-%M-%S)
  BACKUP_FILE="PCAP_BACKUP_$DATE.tar.gz"

  tar -czvf "$BACKUP_FILE" *.pcap &> /dev/null 
  if [[ $? -ne 0 ]]; then
    echo "Error: $0:$LINENO: Something went wrong" 
    exit 1
  fi 

  read -rp "Enter [A] to delete all files or [I] for interactive remove session: " OPT 
  if [[ $OPT == [Aa] ]]; then 
    rm -f *.pcap
    if [[ $? -eq 0 ]]; then 
      echo "All Files Removed Successfully."
    else 
      echo "Error: $0:$LINENO: Something went wrong."
      exit 1 
    fi 
  elif [[ $OPT == [Ii] ]]; then
    rm -i *.pcap 
  else 
    echo "Invalid Option. Try again"
  fi 
}

