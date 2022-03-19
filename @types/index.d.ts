export interface NumpadKeymaps {
  numpad_0: Button;
  numpad_1: Button;
  numpad_2: Button;
  numpad_3: Button;
  numpad_4: Button;
  numpad_5: Button;
  numpad_6: Button;
  numpad_7: Button;
  numpad_8: Button;
  numpad_9: Button;
  numpad_10: Button;
  numpad_11: Button;
  function_12: Button;
  function_13: Button;
  function_14: Button;
  function_15: Button;
  function_16: Button;
}

export interface Button {
  x: number;
  y: number;
}

export interface tkParams {
  initTime: string;
  limitTime: number;
  useSession: boolean;
  useSpace: boolean;
  useGenKey: boolean;
  useTalkBack: boolean;
  java_ver: number;
}

export interface requestParams {
  op: string;
  name: string;
  keyType: string;
  keyboardType: string;
  fieldType: string;
  inputName: string;
  parentKeyboard: boolean;
  transkeyUuid: string;
  exE2E: boolean;
  TK_requestToken: number;
  isCrt: boolean;
  allocationIndex: number;
  initTime: string;
  keyIndex: string;
  talkBack: boolean;
}
