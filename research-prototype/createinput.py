import random

numrows = 65536

modulus = 2**64
mkmod = 2**31
datamod = 2**8

f0 = open("Input-P0-0","w") 

for i in range(numrows):
	#mk = random.randint(0, mkmod-1)
	mk = i % 3
	data = random.randint(0,datamod-1)
	is_trigger = random.randint(0,1)

	if(is_trigger):
		print(mk, is_trigger, data, 0,file=f0)  #data = value
		print(mk, is_trigger, data, 0)
	else:
		print(mk, is_trigger, 0, data,file=f0)  # data = breakdown 
		print(mk, is_trigger, 0, data) 


f0.close()

