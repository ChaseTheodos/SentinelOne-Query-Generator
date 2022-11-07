#!/usr/bin/env python3

import sys, re

# update as modes are added to searchPattern func
acceptedArgs = ['-ip', '-dns', '-sha1', '-sha256', '-md5']

# show user correct usage
def argsHelp():
	print("[-] Incorrect usage!")
	print("[+] Acceptable args: ", end='')
	
	[print(f"{arg}, ", end='') if arg != acceptedArgs[-1] else print(f"{arg}", end='') for arg in acceptedArgs]
	
	print("\n[+] e.g: ./s1QueryBuilder.py -dns file")

def searchPattern(line):
	# check user provided arg
	mode = sys.argv[1]
	# strip string, not needed for all queries
	strp = ''

	# IPs
	if mode == "-ip":
		pattern = "([0-9]+.){4}"
		sub = '[:,"\']'

	# Domains
	elif mode == "-dns":
		pattern = "([://]*)([.]*)([a-z-]+[.])([a-z-]+)([.]*)([a-z]*)"
		sub = "(?:.*//|w{3}[.])"
		# update strip
		strp = "/"

	# Sha1 Hashes
	elif mode == "-sha1":
		pattern = "^([a-z0-9]{40})$"
		sub = ""

	# Sha256 Hashes
	elif mode == "-sha256":
		pattern = "^([a-z0-9]{64})$"
		sub = "" 

	# MD5 Hashes
	elif mode == "-md5":
		pattern = "^([a-z0-9]{32})$"
		sub = ""

	return pattern, sub, strp

def openFile():
	# grab file name from cmd line arg
	fileName = sys.argv[2]

	# open file & print error if unable
	try:
		with open(fileName, 'r') as ips:
			ips = ips.readlines()
	except:
		print("[-] ERROR: Could not open file!")
		sys.exit(0)

	# returns list form of file
	return ips

def extractContent():
	content = openFile()

	# create empty list to hold founds lines
	baddyList = []
	# loop through entries, regex attempts to extracts correct info
	for line in content:
		search, sub, strp = searchPattern(line)
		lineSearch = re.search(f"{search}", line)
		if lineSearch:
			finalFormat = (re.sub(f"{sub}", "", lineSearch.group())).strip(strp)
			if finalFormat not in baddyList:
				# adds formatted line to final list
				baddyList.append(finalFormat)

	# return list
	return baddyList

def queryGen(baddyList):
	# S1 query limitation
	queryThreshold = 99

	# keeps count of entries added
	queryCount = 0

	# keeps track of total query blocks
	queryBlocks = 1
	
	# provided by cmd line arg
	mode = sys.argv[1]

	print("*"*30+f" QUERY #1 "+"*"*30)
	for entry in baddyList:
		# check for beginning of query
		if queryCount == 0:
			print(f'{(mode.strip("-")).upper()} in contains anycase ("{entry}",', end='')
			queryCount += 1
		
		# if not at the end of query length or file
		elif queryCount != queryThreshold and entry != baddyList[-1]:
			print(f'"{entry}",', end='')
			queryCount += 1

		else:
			queryBlocks += 1
			# closes query
			print(f'"{entry}")', end='')

			if entry == baddyList[-1]:
				print("\n"+"*"*32+f" DONE "+"*"*32)
			else:
				print("\n"+"*"*30+f" QUERY #{queryBlocks} "+"*"*30)
			
			# starting new query block, need to reset count
			queryCount = 0

# RUN SCRIPT
if __name__ == "__main__":
	# if right num of args provided
	if len(sys.argv) == 3 and sys.argv[1] in acceptedArgs:
		queryGen(extractContent())
	else:
		# print usage help
		argsHelp()