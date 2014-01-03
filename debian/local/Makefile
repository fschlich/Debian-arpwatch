IEEEFILE = oui.txt
IEEESITE = http://standards.ieee.org/regauth/oui/$(IEEEFILE)
CAVEFILE = Ethernet.txt
#CAVESITE = ftp://ftp.cavebear.com/pub/$(CAVEFILE)
CAVESITE = http://map-ne.com/Ethernet/$(CAVEFILE)
OUTPUT = ethercodes.dat

default: 
	@echo "Huh?"
	@echo "clean grab cook patchcmd"

clean:
	rm -f *.txt

grab: clean
	wget $(IEEESITE)
	wget $(CAVESITE)

cook:
	-cp $(OUTPUT) $(OUTPUT).bak
	perl dmassagevendor --cavebear=$(CAVEFILE) --ieee=$(IEEEFILE) \
		--output=$(OUTPUT)

patchcmd:
	@echo "Run these:"
	@perl patches.pl patches.def

manpage:
	##help2man -N -s 8 ./dmassagevendor > dmassagevendor.8.gen

.PHONY: clean grab cook patchcmd manpage
