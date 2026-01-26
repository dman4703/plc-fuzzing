void MAIN_init__(MAIN *data__, BOOL retain) {
  __INIT_VAR(data__->HIGHT,230,retain)
  __INIT_VAR(data__->LOWT,210,retain)
  __INIT_LOCATED(INT,__MW0,data__->TEMP,retain)
  __INIT_LOCATED_VALUE(data__->TEMP,260)
  __INIT_LOCATED(BOOL,__QX0_0,data__->FANCMD,retain)
  __INIT_LOCATED_VALUE(data__->FANCMD,__BOOL_LITERAL(FALSE))
}

// Code part
void MAIN_body__(MAIN *data__) {
  // Initialise TEMP variables

  if ((__GET_LOCATED(data__->TEMP,) >= __GET_VAR(data__->HIGHT,))) {
    __SET_LOCATED(data__->,FANCMD,,__BOOL_LITERAL(TRUE));
  } else if ((__GET_LOCATED(data__->TEMP,) <= __GET_VAR(data__->LOWT,))) {
    __SET_LOCATED(data__->,FANCMD,,__BOOL_LITERAL(FALSE));
  };

  goto __end;

__end:
  return;
} // MAIN_body__() 





