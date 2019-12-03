Samuel Carroll
CptS 455
Proj 4
12/4/2019

The instructions for this one are pretty simple as long as all of the necessary software is already instlled.

1: Run the command './make' to compile the server and client files.
2: In one terminal run the command './runmn.sh' to start mininet with the proper specifications. 
3: In a separate terminal from step 2 run the command './Pox.sh' to start the Pox controller. 
4: In the running mininet execute the command 'h2 ./server output.txt &' 'h1 ./client 10.0.0.2 tux.txt'
5: To check that it worked close mininet and run the command 'diff output.txt tux.txt', this should return nothing
   if the test was successful. 