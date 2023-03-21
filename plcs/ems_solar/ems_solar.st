PROGRAM My_Program
  VAR
    OnOff AT %QX0.0 : BOOL := 0;
    MaxGen AT %IW0 : INT := 400;
    CurrentGen AT %IW1 : INT := 300;
    ID AT %IW2 : INT := 3;
    TargetGen AT %QW0 : INT := 300;
  END_VAR
  VAR
    Delta : INT := 2;
    Increasing : BOOL := 0;
    Decreasing : BOOL := 0;
    Tick : BOOL := 0;
    Tick_Count : INT := 0;
    TON0 : TON;
    LT48_OUT : BOOL;
    MOVE50_OUT : BOOL;
    GT2_OUT : BOOL;
    MOVE4_OUT : BOOL;
    GT9_OUT : BOOL;
    MOVE11_OUT : BOOL;
    EQ26_OUT : BOOL;
    MOVE28_OUT : BOOL;
    R_TRIG1 : R_TRIG;
    ADD128_OUT : INT;
    SEL129_OUT : INT;
    MOVE133_OUT : INT;
    EQ34_OUT : BOOL;
    MOVE36_OUT : BOOL;
    R_TRIG2 : R_TRIG;
    ADD60_OUT : INT;
    SEL61_OUT : INT;
    MOVE65_OUT : INT;
    R_TRIG3 : R_TRIG;
    SUB15_OUT : INT;
    SEL16_OUT : INT;
    MOVE20_OUT : INT;
    MIN45_OUT : INT;
    MIN79_OUT : INT;
    SUB89_OUT : INT;
    GT93_OUT : BOOL;
    SUB43_OUT : INT;
    LT44_OUT : BOOL;
    AND95_OUT : BOOL;
    SEL96_OUT : INT;
    SUB87_OUT : INT;
    LT94_OUT : BOOL;
    SUB72_OUT : INT;
    LT84_OUT : BOOL;
    AND102_OUT : BOOL;
    SEL103_OUT : INT;
    GT142_OUT : BOOL;
    SEL118_OUT : INT;
    GT125_OUT : BOOL;
    SEL122_OUT : INT;
    SEL120_OUT : INT;
  END_VAR

  LT48_OUT := LT(CurrentGen, TargetGen);
  MOVE50_OUT := MOVE(LT48_OUT);
  IF MOVE50_OUT THEN
    Increasing := TRUE; (*set*)
  END_IF;
  IF MOVE50_OUT THEN
    Decreasing := FALSE; (*reset*)
  END_IF;
  GT2_OUT := GT(CurrentGen, TargetGen);
  MOVE4_OUT := MOVE(GT2_OUT);
  IF MOVE4_OUT THEN
    Increasing := FALSE; (*reset*)
  END_IF;
  IF MOVE4_OUT THEN
    Decreasing := TRUE; (*set*)
  END_IF;
  TON0(IN := NOT(Tick), PT := T#2000ms);
  Tick := TON0.Q;
  GT9_OUT := GT(CurrentGen, MaxGen);
  MOVE11_OUT := MOVE(GT9_OUT);
  IF MOVE11_OUT THEN
    Increasing := FALSE; (*reset*)
  END_IF;
  IF MOVE11_OUT THEN
    Decreasing := TRUE; (*set*)
  END_IF;
  EQ26_OUT := EQ(CurrentGen, MaxGen);
  MOVE28_OUT := MOVE(EQ26_OUT);
  IF MOVE28_OUT THEN
    Increasing := FALSE; (*reset*)
  END_IF;
  R_TRIG1(CLK := Tick);
  ADD128_OUT := ADD(1, Tick_Count);
  SEL129_OUT := SEL(R_TRIG1.Q AND 1, Tick_Count, ADD128_OUT);
  MOVE133_OUT := MOVE(SEL129_OUT);
  Tick_Count := MOVE133_OUT;
  EQ34_OUT := EQ(CurrentGen, TargetGen);
  MOVE36_OUT := MOVE(EQ34_OUT);
  IF MOVE36_OUT THEN
    Increasing := FALSE; (*reset*)
  END_IF;
  IF MOVE36_OUT THEN
    Decreasing := FALSE; (*reset*)
  END_IF;
  R_TRIG2(CLK := Tick);
  ADD60_OUT := ADD(CurrentGen, Delta);
  SEL61_OUT := SEL(R_TRIG2.Q AND Increasing, CurrentGen, ADD60_OUT);
  MOVE65_OUT := MOVE(SEL61_OUT);
  CurrentGen := MOVE65_OUT;
  R_TRIG3(CLK := Tick);
  SUB15_OUT := SUB(CurrentGen, Delta);
  SEL16_OUT := SEL(R_TRIG3.Q AND Decreasing, CurrentGen, SUB15_OUT);
  MOVE20_OUT := MOVE(SEL16_OUT);
  CurrentGen := MOVE20_OUT;
  MIN45_OUT := MIN(TargetGen, MaxGen);
  TargetGen := MIN45_OUT;
  MIN79_OUT := MIN(CurrentGen, MaxGen);
  CurrentGen := MIN79_OUT;
  SUB89_OUT := SUB(TargetGen, CurrentGen);
  GT93_OUT := GT(SUB89_OUT, 0);
  SUB43_OUT := SUB(TargetGen, CurrentGen);
  LT44_OUT := LT(SUB43_OUT, Delta);
  AND95_OUT := AND(GT93_OUT, LT44_OUT);
  SEL96_OUT := SEL(Decreasing AND AND95_OUT, CurrentGen, TargetGen);
  CurrentGen := SEL96_OUT;
  SUB87_OUT := SUB(TargetGen, CurrentGen);
  LT94_OUT := LT(SUB87_OUT, 0);
  SUB72_OUT := SUB(TargetGen, CurrentGen);
  LT84_OUT := LT(SUB72_OUT, Delta);
  AND102_OUT := AND(LT94_OUT, LT84_OUT);
  SEL103_OUT := SEL(Increasing AND AND102_OUT, CurrentGen, TargetGen);
  CurrentGen := SEL103_OUT;
  GT142_OUT := GT(Tick_Count, 9000);
  SEL118_OUT := SEL(GT142_OUT, TargetGen, 0);
  TargetGen := SEL118_OUT;
  GT125_OUT := GT(Tick_Count, 18000);
  SEL122_OUT := SEL(GT125_OUT, TargetGen, 300);
  TargetGen := SEL122_OUT;
  SEL120_OUT := SEL(GT125_OUT, Tick_Count, 0);
  Tick_Count := SEL120_OUT;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK TaskMain(INTERVAL := T#50ms,PRIORITY := 0);
    PROGRAM Inst0 WITH TaskMain : My_Program;
  END_RESOURCE
END_CONFIGURATION
