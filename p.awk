# Only print the first ethernet address seen

{
	e = $1
	if (seen[e])
		continue
	seen[e] = 1
	print $0
}
