# GPU-monitor
A tool to visualize the current usage of GPU and CPU in Morilab

This tool visualizes the CPU and GPU status of specified servers. It connects to the designated server using the provided username and password, then displays the currently logged-in users and running processes.
Built primarily using Python and Streamlit, the application polls the server every second by default to retrieve the latest status and caches the data locally; this prevents redundant server requests from multiple terminal sessions, thereby avoiding server congestion. For processes, the tool displays details such as start time and owner (processes without an owner are identified as zombie processes). Server information, including current temperatures, is also displayed. While the initial startup may take around 30 seconds, subsequent operations are faster (under 5 seconds), and the tool automatically refreshes data for all servers.
