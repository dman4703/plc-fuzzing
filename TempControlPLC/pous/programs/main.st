PROGRAM main
VAR
	Temp : int AT %MW0 := 260; (* Simulated temperature in tenths of °C *)
	FanCmd : bool AT %QX0.0 := FALSE; (* Cooling fan ON/OFF output *)
	HighT : int := 230; (* High threshold = 23.0 °C *)
	LowT : int := 210; (* Low threshold = 21.0 °C *)
END_VAR

(* If temp is high enough, turn fan ON *)
IF Temp >= HighT THEN
    FanCmd := TRUE;

(* If tempe is low enough, turn fan OFF *)
ELSIF Temp <= LowT THEN
    FanCmd := FALSE;
END_IF;

END_PROGRAM