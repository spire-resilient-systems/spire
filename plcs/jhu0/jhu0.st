PROGRAM My_Program
  VAR
    transformer AT %QX0.0 : BOOL := 1;
    switch1 AT %QW0 : INT := 1;
  END_VAR
  VAR
    switch2 AT %QW1 : INT := 1;
  END_VAR
  VAR
    TON0 : TON;
    TON1 : TON;
    NE16_OUT : BOOL;
    SEL10_OUT : INT;
    MOVE14_OUT : INT;
    EQ21_OUT : BOOL;
    SEL3_OUT : INT;
    MOVE7_OUT : INT;
  END_VAR

  NE16_OUT := NE(switch1, 2);
  TON0(IN := NE16_OUT, PT := T#20000ms);
  SEL10_OUT := SEL(TON0.Q, switch1, 2);
  MOVE14_OUT := MOVE(SEL10_OUT);
  switch1 := MOVE14_OUT;
  EQ21_OUT := EQ(switch1, 2);
  TON1(IN := EQ21_OUT, PT := T#20000ms);
  SEL3_OUT := SEL(TON1.Q, switch1, 0);
  MOVE7_OUT := MOVE(SEL3_OUT);
  switch1 := MOVE7_OUT;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK TaskMain(INTERVAL := T#50ms,PRIORITY := 0);
    PROGRAM Inst0 WITH TaskMain : My_Program;
  END_RESOURCE
END_CONFIGURATION
