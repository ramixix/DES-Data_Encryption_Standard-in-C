CC=gcc			#set compilter to gcc
flags=-lm		#link to the math library
output_file_name=run	# name of output binary

all:
	$(CC) main.c des.c $(flags) -o $(output_file_name) -g
clean:
	rm $(output_file_name)

