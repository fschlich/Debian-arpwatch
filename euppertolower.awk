BEGIN {
	x["A"] = "a"
	x["B"] = "b"
	x["C"] = "c"
	x["D"] = "d"
	x["E"] = "e"
	x["F"] = "f"

}

{
	s = ""
	for (i = 1; i <= 6; ++i) {
		t = substr($0, i, 1)
		if (x[t] != "")
			s = s x[t]
		else
			s = s t
	}
	s = s substr($0, 7)
	print s
	next
}
