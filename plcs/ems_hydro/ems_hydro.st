PROGRAM My_Program
  VAR
    OnOff AT %QX0.0 : BOOL := 0;
    MaxGen AT %IW0 : INT := 400;
    CurrentGen AT %IW1 : INT := 400;
    ID AT %IW2 : INT := 4;
    TargetGen AT %QW0 : INT := 400;
  END_VAR
  VAR
    Delta : INT := 250;
    Increasing : BOOL := 0;
    Decreasing : BOOL := 0;
    Tick : BOOL := 0;
    TON0 : TON;
  END_VAR

  TON0(IN := NOT(Tick), PT := T#2000ms);
  Tick := TON0.Q;
  CurrentGen := TargetGen;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK TaskMain(INTERVAL := T#50ms,PRIORITY := 0);
    PROGRAM Inst0 WITH TaskMain : My_Program;
  END_RESOURCE
END_CONFIGURATION
