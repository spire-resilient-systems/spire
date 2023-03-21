PROGRAM My_Program
  VAR
    B10_1_Opened AT %IX0.0 : BOOL := 0;
    B10_1_Closed AT %IX0.1 : BOOL := 1;
    B10_2_Opened AT %IX0.2 : BOOL := 0;
    B10_2_Closed AT %IX0.3 : BOOL := 1;
    B10_12_Opened AT %IX0.4 : BOOL := 1;
    B10_12_Closed AT %IX0.5 : BOOL := 0;
    B54_Opened AT %IX0.6 : BOOL := 0;
    B54_Closed AT %IX0.7 : BOOL := 1;
    B55_Opened AT %IX1.0 : BOOL := 0;
    B55_Closed AT %IX1.1 : BOOL := 1;
    B56_Opened AT %IX1.2 : BOOL := 0;
    B56_Closed AT %IX1.3 : BOOL := 1;
    B57_Opened AT %IX1.4 : BOOL := 0;
    B57_Closed AT %IX1.5 : BOOL := 1;
    B10_1_Trip AT %QX0.0 : BOOL := 0;
    B10_1_Close AT %QX0.1 : BOOL := 0;
    B10_2_Trip AT %QX0.2 : BOOL := 0;
    B10_2_Close AT %QX0.3 : BOOL := 0;
    B10_12_Trip AT %QX0.4 : BOOL := 0;
    B10_12_Close AT %QX0.5 : BOOL := 0;
    B54_Trip AT %QX0.6 : BOOL := 0;
    B54_Close AT %QX0.7 : BOOL := 0;
    B55_Trip AT %QX1.0 : BOOL := 0;
    B55_Close AT %QX1.1 : BOOL := 0;
    B56_Trip AT %QX1.2 : BOOL := 0;
    B56_Close AT %QX1.3 : BOOL := 0;
    B57_Trip AT %QX1.4 : BOOL := 0;
    B57_Close AT %QX1.5 : BOOL := 0;
    Point_1a AT %QW0 : INT := 138;
    Point_1b AT %QW1 : INT := 0;
    Point_2a AT %QW2 : INT := 138;
    Point_2b AT %QW3 : INT := 0;
    Point_3a AT %QW4 : INT := 138;
    Point_3b AT %QW5 : INT := 0;
    Point_4a AT %QW6 : INT := 138;
    Point_4b AT %QW7 : INT := 0;
    Point_5a AT %QW8 : INT := 0;
    Point_5b AT %QW9 : INT := 0;
    Point_6a AT %QW10 : INT := 0;
    Point_6b AT %QW11 : INT := 0;
    Point_7a AT %QW12 : INT := 0;
    Point_7b AT %QW13 : INT := 0;
    Point_8a AT %QW14 : INT := 0;
    Point_8b AT %QW15 : INT := 0;
  END_VAR
  VAR
    SEL86_OUT : INT;
    MOVE89_OUT : INT;
    SEL66_OUT : INT;
    MOVE69_OUT : INT;
    SEL96_OUT : INT;
    MOVE99_OUT : INT;
    SEL106_OUT : INT;
    MOVE109_OUT : INT;
  END_VAR

  IF B10_1_Close THEN
    B10_1_Closed := TRUE; (*set*)
  END_IF;
  IF B10_2_Close THEN
    B10_2_Closed := TRUE; (*set*)
  END_IF;
  IF B10_12_Close THEN
    B10_12_Closed := TRUE; (*set*)
  END_IF;
  IF B10_1_Close THEN
    B10_1_Opened := FALSE; (*reset*)
  END_IF;
  IF B10_2_Close THEN
    B10_2_Opened := FALSE; (*reset*)
  END_IF;
  IF B10_12_Close THEN
    B10_12_Opened := FALSE; (*reset*)
  END_IF;
  IF B10_1_Trip THEN
    B10_1_Closed := FALSE; (*reset*)
  END_IF;
  IF B10_2_Trip THEN
    B10_2_Closed := FALSE; (*reset*)
  END_IF;
  IF B10_12_Trip THEN
    B10_12_Closed := FALSE; (*reset*)
  END_IF;
  IF B10_1_Trip THEN
    B10_1_Opened := TRUE; (*set*)
  END_IF;
  IF B10_2_Trip THEN
    B10_2_Opened := TRUE; (*set*)
  END_IF;
  IF B10_12_Trip THEN
    B10_12_Opened := TRUE; (*set*)
  END_IF;
  IF B54_Close THEN
    B54_Closed := TRUE; (*set*)
  END_IF;
  IF B55_Close THEN
    B55_Closed := TRUE; (*set*)
  END_IF;
  IF B56_Close THEN
    B56_Closed := TRUE; (*set*)
  END_IF;
  IF B54_Close THEN
    B54_Opened := FALSE; (*reset*)
  END_IF;
  IF B55_Close THEN
    B55_Opened := FALSE; (*reset*)
  END_IF;
  IF B56_Close THEN
    B56_Opened := FALSE; (*reset*)
  END_IF;
  IF B54_Trip THEN
    B54_Closed := FALSE; (*reset*)
  END_IF;
  IF B55_Trip THEN
    B55_Closed := FALSE; (*reset*)
  END_IF;
  IF B56_Trip THEN
    B56_Closed := FALSE; (*reset*)
  END_IF;
  IF B54_Trip THEN
    B54_Opened := TRUE; (*set*)
  END_IF;
  IF B55_Trip THEN
    B55_Opened := TRUE; (*set*)
  END_IF;
  IF B56_Trip THEN
    B56_Opened := TRUE; (*set*)
  END_IF;
  SEL86_OUT := SEL(B54_Closed AND (B10_12_Closed AND B10_1_Closed OR B10_2_Closed), 0, 138);
  MOVE89_OUT := MOVE(SEL86_OUT);
  Point_1a := MOVE89_OUT;
  IF B57_Close THEN
    B57_Closed := TRUE; (*set*)
  END_IF;
  IF B57_Close THEN
    B57_Opened := FALSE; (*reset*)
  END_IF;
  IF B57_Trip THEN
    B57_Closed := FALSE; (*reset*)
  END_IF;
  IF B57_Trip THEN
    B57_Opened := TRUE; (*set*)
  END_IF;
  SEL66_OUT := SEL(B55_Closed AND (B10_12_Closed AND B10_1_Closed OR B10_2_Closed), 0, 138);
  MOVE69_OUT := MOVE(SEL66_OUT);
  Point_2a := MOVE69_OUT;
  SEL96_OUT := SEL(B56_Closed AND (B10_12_Closed AND B10_2_Closed OR B10_1_Closed), 0, 138);
  MOVE99_OUT := MOVE(SEL96_OUT);
  Point_3a := MOVE99_OUT;
  SEL106_OUT := SEL(B57_Closed AND (B10_12_Closed AND B10_2_Closed OR B10_1_Closed), 0, 138);
  MOVE109_OUT := MOVE(SEL106_OUT);
  Point_4a := MOVE109_OUT;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK TaskMain(INTERVAL := T#20ms,PRIORITY := 0);
    PROGRAM Inst0 WITH TaskMain : My_Program;
  END_RESOURCE
END_CONFIGURATION
