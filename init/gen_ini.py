 #
 # Spire.
 #
 # The contents of this file are subject to the Spire Open-Source
 # License, Version 1.0 (the ``License''); you may not use
 # this file except in compliance with the License.  You may obtain a
 # copy of the License at:
 #
 # http://www.dsn.jhu.edu/spire/LICENSE.txt 
 #
 # or in the file ``LICENSE.txt'' found in this distribution.
 #
 # Software distributed under the License is distributed on an AS IS basis, 
 # WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 # for the specific language governing rights and limitations under the 
 # License.
 #
 # Spire is developed at the Distributed Systems and Networks Lab,
 # Johns Hopkins University and the Resilient Systems and Societies Lab,
 # University of Pittsburgh.
 #
 # Creators:
 #   Yair Amir            yairamir@cs.jhu.edu
 #   Trevor Aron          taron1@cs.jhu.edu
 #   Amy Babay            babay@pitt.edu
 #   Thomas Tantillo      tantillo@cs.jhu.edu 
 #   Sahiti Bommareddy    sahiti@cs.jhu.edu
 #   Maher Khan           maherkhan@pitt.edu
 #
 # Major Contributors:
 #   Marco Platania       Contributions to architecture design 
 #   Daniel Qian          Contributions to Trip Master and IDS 

 #
 # Contributors:
 #   Samuel Beckley       Contributions HMIs
 
 #
 # Copyright (c) 2017-2025 Johns Hopkins University.
 # All rights reserved.
 #
 # Partial funding for Spire research was provided by the Defense Advanced 
 # Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 # Department of Energy (DoE).
 # Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
 #
 #

#generate init file

class Substation(object):
    def __init__(self):
        self.box_id = -1
        self.tx_id = -1
        self.switches = []
        self.lines =[]

    #print substation
    def s_print(self):
        print "#SUB ID"
        print str(self.box_id)
        print "#TX ID"
        print str(self.tx_id)
        print "#NUMBER OF SWITCHES"
        print str(len(self.switches))
        print "#SWITCH IDS"
        for switch in self.switches:
            print str(switch)
        print "#NUMBER OF LINES"
        print str(len(self.lines))
        for line in self.lines:
            line.l_print()

class Line(object):
    def __init__(self, tup, dest_sub, l_id):
        self.src = tup[0]
        self.dest = tup[1]
        self.src_switch_id = -1
        self.dest_switch_id = -1
        self.dest_sub_id = dest_sub
        self.l_id = l_id

    def l_print(self):
        print "#LINE INFO"
        print str(self.l_id)
        print str(self.src_switch_id)
        print str(self.dest_switch_id)
        print str(self.dest_sub_id)

def main():
    w_names = []
    sub_map = {"sp":0,"s1":1,"s2":2,"s3":3,"s4":4,"p":5,"m":6,"u":7,"r":8,"f":9}
    line_set = set()
    
    #read names from file
    with open("widget_names.txt") as file:
        for line in file:
            temp = line.rstrip('\n')
            w_names.append(temp)

    #Number of each
    number_tot = 0
    number_tx = 0
    number_line = 0
    number_box = 0
    number_switch = 0

    sub_arr = []
    line_arr = []
    for i in range(10):
        sub_arr.append(Substation())

    #dicts from representation to id#
    #rep = tuple(s1,s2)
    switch_map = {}

    line_to_ttiparr_pos = {}

    #tooltip_arr
    #tuple of (type, list)
    tooltip_arr = []
    ttip = 0
    counter = 0
    #find number of uniques
    for name in w_names:
        #ignore these guys
        if "key" in name:
            pass
        #transformer
        elif "power" in name:
            number_tx += 1
            element = (1, [ttip])
            tooltip_arr.append(element)
            
            sub_arr[sub_map[name.split("_")[0]]].tx_id = counter
            counter += 1
        #box
        elif "box" in name:
            number_box += 1
            element = (0, [ttip])
            tooltip_arr.append(element)

            sub_arr[sub_map[name.split("_")[0]]].box_id = counter
            counter += 1
        #switch
        elif "switch" in name:
            number_switch +=1
            tup = (name.split("_")[1], name.split("_")[2])
            switch_map[tup] = counter
            sub_arr[sub_map[name.split("_")[1]]].switches.append(counter)
            element = (2, [ttip])
            tooltip_arr.append(element)
            counter += 1
        #line
        elif "line" in name:
            str_a = name.split("_")
            tup = (str_a[1],str_a[2])
            if tup not in line_set:
                line_set.add(tup)
                number_line +=1

                element = (3, [ttip])
                tooltip_arr.append(element)
                sub_arr[sub_map[str_a[1]]].lines.append(Line(tup, sub_map[str_a[2]], counter))
                line_to_ttiparr_pos[tup] = counter
                counter += 1
            else:
                element = tooltip_arr[line_to_ttiparr_pos[tup]]
                element[1].append(ttip)
        ttip += 1
    #finish up some things
    for sub in sub_arr:
        for line in sub.lines:
            src_tup = (line.src, line.dest)
            dest_tup = (line.dest, line.src)
            line.src_switch_id = switch_map[src_tup]
            line.dest_switch_id = switch_map[dest_tup]
    #print EVERYTHING
    print "#SIZE OF TOOLTIP ARRAY"
    print counter
    print "#TOOLTIP ARRAY"
    for el in tooltip_arr:
        t_string = "" + str(el[0])
        for i in el[1]:
            t_string += " " + str(i)
        print t_string
    print "#_____________________"
    print len(sub_arr)
    for sub in sub_arr:
        sub.s_print()

if __name__ == "__main__":
    main()
