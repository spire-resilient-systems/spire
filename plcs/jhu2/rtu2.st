PROGRAM My_Program
  VAR
    transformer AT %QX0.0 : BOOL := 1;
    switch1 AT %QW0 : INT := 1;
    switch2 AT %QW1 : INT := 1;
    switch3 AT %QW2 : INT := 1;
    switch4 AT %QW3 : INT := 0;
    switch5 AT %QW4 : INT := 0;
  END_VAR

  switch5 := switch5;
END_PROGRAM


CONFIGURATION Config0

  RESOURCE Res0 ON PLC
    TASK TaskMain(INTERVAL := T#50ms,PRIORITY := 0);
    PROGRAM Inst0 WITH TaskMain : My_Program;
  END_RESOURCE
END_CONFIGURATION
