#####################################
#            Simple IDS             #
#          20154553 Inho Cho        #
#          inho00@kaist.ac.kr       #
#        IS539 Network Security     #
#           Assignment #1           #
#####################################


<Simple IDS>
This is very simple intrusion detection system (IDS) which captures the packets from network interface card and examine whether there exist suspicious packets based on IDS rules. 


< How to install >
1.Make sure you have installed 'libpcap-dev' library before you install Simple IDS. If you don't have 'libpcap-dev' library, install with following command

   # sudo apt-get install libpcap-dev

2. Compile the source code with Makefile with 'make' command

   #make

3. Or simply you can run ./install 

   #./install

Note that ./install.sh requires sudo permission.


< How to run >
If you install and compile the code correctly, executable file name 'simpleids' will be created in the root directory.
Move to the root directory for executing Simple IDS with following command.

   #sudo ./simpleids [-i iface_dev_name] rule_file

For example, you can run Simpleids with

	#sudo ./simpleids rule_file
	#sudo ./simpleids -i eth0 rule_file

You can notify explicitly on which network interface card you want to execute simple IDS. 
If -i option is not given, it automatically selects appropriate device with pcap_lookupdev() function. 
To execute Simpleids you need sudo permission on the machine.


< How to terminate>
You can terminate the Simple IDS program by giving SIGINT singal to the program with "Ctrl+C".
SimpleIDS get SIGINT signal and terminates the program in appropriate way.


< About IDS rules >
Basically it follows snort rule, but its rule is simplified as described in the assignment instruction.
Basic IDS rule grammar as follows

alert <protocol> <source IP> <source port> -> <destination IP> <destination port> (field1:value1;field2:value2;)

Note that Simpleids only supports tcp protocol. 
Make sure each pattern(field:value;) ends with semicolon.
"IP length" is not supported in Simpleids because snort IDS rule does not support this.
In the rule_file you should declare one IDS rule in one line. You cannot divide one IDS rule into more than one line.
Example rule file is given with the file named 'rule_file'.


< References >
The portion of codes which prints the payload is borrowed from http://www.tcpdump.org/sniffex.c 
