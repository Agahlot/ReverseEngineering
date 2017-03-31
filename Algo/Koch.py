from turtle import *

bgcolor("white"); color("red");
setup(width=999, height=999, startx=0, starty=0); screensize(9999,9999);
hideturtle(); speed(0); pensize(0);
up(); setposition(-500, -200); down()

def Koch(n, s):
	if n == s:
		forward(100 / ((n * 3) + 1))
		left(60)
		forward(100 / ((n * 3) + 1))
		right(120)
		forward(100 / ((n * 3) + 1))
		left(60)
		forward(100 / ((n * 3) + 1))
		return
	else:
		Koch(n + 1, s)
		left(60)
		Koch(n + 1, s)
		right(120)
		Koch(n + 1, s)
		left(60)
		Koch(n + 1, s)
	return

Koch(0, 7)

ts = getscreen()
ts.getcanvas().postscript(file="Koch.eps")
done()