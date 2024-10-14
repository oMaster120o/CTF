CC = gcc

all: files
	@${CC} format-string-1.c -o vuln

files:
	@touch secret-menu-item-1.txt secret-menu-item-2.txt flag.txt 
	@echo "SECRET MENU ITEM1" > secret-menu-item-1.txt
	@echo "SECRET MENU ITEM2" > secret-menu-item-2.txt
	@echo "pico{fake flag}"   > flag.txt
