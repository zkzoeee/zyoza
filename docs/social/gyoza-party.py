import sys
R=[]
def r(x,y,w,h,c): R.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{c}"/>')
INK='#0E1015'
def noggles(ox,oy,frame,style):
    for a in [(5,12,4,1),(5,13,1,3),(16,12,1,1),(9,10,7,7),(17,10,7,7)]: r(ox+a[0],oy+a[1],a[2],a[3],frame)
    r(ox+10,oy+11,5,5,INK); r(ox+18,oy+11,5,5,INK)
    if style=='venetian':
        r(ox+10,oy+11,5,5,frame); r(ox+18,oy+11,5,5,frame)
        for y in (11,13,15): r(ox+10,oy+y,5,1,INK); r(ox+18,oy+y,5,1,INK)
    elif style=='mesh':
        for y in range(11,16):
            for x in list(range(10,15))+list(range(18,23)):
                if (x+y)%2==0: r(ox+x,oy+y,1,1,frame)
    elif style=='noun':
        for x in (10,18):
            r(ox+x,oy+11,2,5,'#FFFFFF'); r(ox+x+2,oy+11,3,5,'#111111')
    else:
        r(ox+10,oy+11,5,5,frame)
        for y in (11,13,15): r(ox+10,oy+y,5,1,INK)
        r(ox+18,oy+11,2,5,'#FFFFFF'); r(ox+20,oy+11,3,5,'#111111')
def gyoza(x,y,outline=True):
    if outline: r(x,y+3,8,1,'#7A5330')
    r(x+2,y,4,1,'#E6C79C'); r(x+1,y+1,6,1,'#F6EFE2'); r(x,y+2,8,1,'#F6EFE2')
    r(x+3,y,1,1,'#CBBFA8'); r(x+2,y+1,1,1,'#D9B382'); r(x+5,y+1,1,1,'#D9B382')
    r(x,y+3 if not outline else y+2,8,1,'#D9A066') if not outline else r(x+1,y+2,6,1,'#EBD3A8')
def eat(ox,oy,skin,gy=19):
    gyoza(ox+19,oy+gy)
    for i in range(8):
        r(ox+26+round(i*0.6),oy+gy+2+i,1,1,'#8A5A10')
        r(ox+24+round(i*0.9),oy+gy+3+i,1,1,'#6B450C')
def dumpling(ox,oy):
    for a in [(7,23,18,9,'#23262F'),(9,25,14,2,'#F4B728'),(9,28,14,1,'#C53D2F'),(11,22,10,2,'#D9B382'),
      (9,5,2,2,'#D9B382'),(12,4,2,3,'#E6C79C'),(15,4,2,3,'#D9B382'),(18,4,2,3,'#E6C79C'),(21,5,2,2,'#D9B382'),
      (7,7,18,14,'#F6EFE2'),(6,10,20,9,'#F6EFE2'),(8,20,16,2,'#F6EFE2'),(9,21,14,1,'#E6C79C'),
      (11,6,1,2,'#CBBFA8'),(14,6,1,2,'#CBBFA8'),(17,6,1,2,'#CBBFA8'),(20,6,1,2,'#CBBFA8'),(14,19,4,1,'#5C5346')]:
        r(ox+a[0],oy+a[1],a[2],a[3],a[4])
    noggles(ox,oy,'#F4B728','venetian')
def zakura(ox,oy):
    for a in [(7,23,18,9,'#2B2230'),(9,27,14,2,'#E0527A'),(15,23,2,4,'#F9D5DC'),(11,22,10,2,'#F3D9DC')]:
        r(ox+a[0],oy+a[1],a[2],a[3],a[4])
    for i,(x,y) in enumerate([(6,4),(10,3),(14,2),(18,3),(22,4)]):
        c='#F29DB2' if i%2==0 else '#F7B9C8'
        r(ox+x,oy+y+1,4,7-y,c); r(ox+x,oy+y,1,1,c); r(ox+x+3,oy+y,1,1,c)
    for a in [(7,7,18,14,'#FBDDE3'),(6,10,20,9,'#FBDDE3'),(8,20,16,2,'#F2C2CD'),(15,7,2,1,'#F4B728'),
      (7,18,2,1,'#F29DB2'),(23,18,2,1,'#F29DB2'),(14,19,4,1,'#A84A63')]:
        r(ox+a[0],oy+a[1],a[2],a[3],a[4])
    noggles(ox,oy,'#E0527A','noun')
def zebra(ox,oy):
    K='#171614'
    for a in [(7,23,18,9,'#F4F1EA'),(7,25,18,1,K),(7,28,18,1,K),(7,31,18,1,K),(11,22,10,2,'#E3DFD5'),
      (8,3,3,5,K),(9,4,1,2,'#F29DB2'),(21,3,3,5,K),(22,4,1,2,'#F29DB2'),(14,2,4,6,K),(13,4,6,3,K),
      (7,7,18,14,'#FAF8F3'),(6,10,20,9,'#FAF8F3'),
      (9,8,3,1,K),(20,8,3,1,K),(14,7,4,2,K),
      (6,11,2,1,K),(6,14,2,1,K),(6,17,3,1,K),(24,11,2,1,K),(24,14,2,1,K),(23,17,3,1,K),
      (10,18,12,4,'#34322F'),(12,19,1,1,'#8F8B84'),(19,19,1,1,'#8F8B84'),(14,21,4,1,K)]:
        r(ox+a[0],oy+a[1],a[2],a[3],a[4])
    noggles(ox,oy,'#C53D2F','mesh')

W,H=128,72
# falling petals
for x,y in [(8,10),(20,22),(31,6),(40,30),(52,3),(77,5),(84,26),(96,9),(109,20),(122,14),(118,34),(4,36),(45,12),(101,36)]:
    r(x,y,2,1,'#F29DB2'); r(x+1,y+1,1,1,'#F7B9C8')
dumpling(10,14); zakura(48,14); zebra(86,14)
# table
r(0,44,W,28,'#23262F'); r(0,44,W,1,'#3D4350')
# plate + gyozas + steam
r(42,51,44,1,'#CFC8B8'); r(40,52,48,2,'#FAF8F3'); r(42,54,44,1,'#B9B2A2')
for x in (44,53,62,71): gyoza(x,48,False)
# sauce dishes + chopstick rests
for x in (20,98):
    r(x,52,10,2,'#FAF8F3'); r(x+2,52,6,1,'#7A2018')
open(sys.argv[1],'w').write(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" shape-rendering="crispEdges"><rect width="128" height="72" fill="#DDD6C7"/>'+''.join(R)+'</svg>')
