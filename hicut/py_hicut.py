import sys
import math
import matplotlib.pyplot as plt

class rule():
    def __init__(self, string):
        self.parse_string(string)

    def parse_string(self, string):
        l = string.replace(' ','').replace('\t\n','').replace('@','').split('\t')
        self.ori_ele = l
        self.src_ip = self.ip2int(l[0].split('/')[0])
        self.src_len = int(l[0].split('/')[1])
        self.dst_ip = self.ip2int(l[1].split('/')[0])
        self.dst_len = int(l[1].split('/')[1])

        self.src_port_begin = int(l[2].split(':')[0])
        self.src_port_end = int(l[2].split(':')[1])
        self.dst_port_begin = int(l[3].split(':')[0])
        self.dst_port_end = int(l[3].split(':')[1])

        self.protocol = (int(l[4][2:4], 16)<<8) + int(l[4][7:],16)

    def ip2int(self, string):
        l = [int(a) for a in string.split('.')]
        return (l[0]<<24) + (l[1]<<16) + (l[2]<<8) + l[3]


def num_child(rules):
    childrens = []
    for i in range(1,6):
        np = pick_np(i, rules)
        #print(f"np: {np}")
        children = [0 for j in range(np)]
        for r in rules:
            index = 0
            copy_time = 1
            if i < 3:
                ip = r.src_ip if i == 1 else r.dst_ip
                l = r.src_len if i == 1 else r.dst_len
                index = ip >> (32 - int(math.log2(np)))
                if (np >> l) > 0:
                    copy_time = np >> l
                else:
                    copy_time = 1
            elif i < 5:
                pb = r.src_port_begin if i == 3 else r.dst_port_begin
                pe = r.src_port_end if i == 3 else r.dst_port_end
                copyt_time = (pe // (65536 // np)) - (pb // (65536 // np))+1
                index = pb // (65536 // np)
            elif i == 5:
                index = r.protocol // (65536 // np)
                copy_time = 1

            if copy_time == 0:
                print("copy_time == 0")
                sys.exit(1)
                

            for j in range(copy_time):
                children[index+j] += 1;
        childrens.append(children)
        #plt.plot(range(0, 65536, 65536//np), children)
    return childrens

def pick_dimension_1(rules):
    max_rules = [max(c) for c in num_child(rules)]

    # plt.show()
    return max_rules.index(min(max_rules))+1

def pick_dimension_2(rules):
    childrens = num_child(rules)
    np = [pick_np(i, rules) for i in range(1,6)]
    sm = [cal_sm(i, np[i-1], rules) for i in range(1,6)]
    h = [0 for i in range(0,5)]
    for i in range(0,5):
        y = [c/sm[i] for c in childrens[i]]
        # plt.subplot(3,2,i+1)
        for yy in y:
            h[i] += -(yy*math.log2(yy)) if yy != 0 else 0
        # plt.plot(range(0,np[i]), childrens[i])
        

    # plt.show()

    return h.index(max(h))+1

def pick_dimension_3(rules):
    sm = [cal_sm(i, pick_np(i, rules), rules) for i in range(1,6)]
    #print(sm)
    return sm.index(min(sm))

def pick_dimension_4(rules):
    # axis5 = [[],[],[],[],[]]
    axis5 = [list() for i in range(5)]
    for r in rules:
        for i in range(5):
            if r.ori_ele[i] not in axis5[i]:
                axis5[i].append(r.ori_ele[i])

    distinct_num = [len(n) for n in axis5]
    #print(distinct_num)

    return distinct_num.index(max(distinct_num))+1

def cal_sm(dim, np, rules):
    sm = 0
    if dim == 1:
        for r in rules:
            if 2 ** r.src_len <= np:
                sm += np / (2**(r.src_len))
            else:
                sm += 1
    elif dim == 2:
        for r in rules:
            if 2 ** r.dst_len <= np:
                sm += np / (2**(r.dst_len))
            else:
                sm += 1
    elif dim == 3:
        for r in rules:
            sm += ((r.src_port_end - r.src_port_begin)//(65536//np))+1;
    elif dim == 4:
        for r in rules:
            sm += ((r.dst_port_end - r.dst_port_begin)//(int(65536//np)))+1;
    elif dim == 5:
        sm += len(rules)

    return sm+np
def pick_np(dim, rules):
    nump = max(4, len(rules)**2)
    spfac = 8
    spmf = len(rules) * spfac
    # print(f"spmf:{spmf}, dim:{dim}")
    sm = 0
    np = 1
    while sm < spmf:
        np *= 2
        sm = cal_sm(dim, np, rules)

    return np

def main():
    f = open(sys.argv[1], "r")

    lines = f.readlines()
    rules = [rule(l) for l in lines]    
    
    dim = pick_dimension_1(rules)
    print("1. ", dim)
    dim = pick_dimension_2(rules)
    print("2. ", dim)
    dim = pick_dimension_3(rules)
    print("3. ", dim)
    dim = pick_dimension_4(rules)
    print("4. ", dim)

    # np = pick_np(dim, rules)
    # print(np);
    cs = num_child(rules)
    np = [pick_np(d, rules) for d in range(1,6)]
    for i in range(0,5):
        plt.subplot(3,2,i+1)
        plt.plot(range(0,np[i]), cs[i])

    plt.show()





if __name__ == "__main__":
    main()
