def partition(L, start, end):
	pivot = end
	wall = start
	for i in range (start, end):
		if L[i] < L[pivot]:
			#switch index
			tmp = L[i]
			L[i] = L[wall]
			L[wall] = tmp
			wall += 1
	#switch pivot
	tmp = L[pivot]
	L[pivot] = L[wall]
	L[wall] = tmp
	return wall

def quicksort(L, start, end):
	p = 0
	if (end - start) >= 1:
		p = partition(L, start, end)
		#recursive
		quicksort(L, start, p - 1)
		quicksort(L, p + 1, end)

def q(L):
	quicksort(L, 0, len(L) - 1)