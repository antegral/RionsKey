import { NumpadKeymaps, tkParams, requestParams, Button } from '../@types';
import {
  BooleanLiteral,
  Identifier,
  NumericLiteral,
  StringLiteral,
  VariableDeclaration,
} from '@babel/types';

import got from 'got';
import crypto from 'crypto';
import { parse } from '@babel/parser';
import rionsKeyEncLib from 'rionskey-seed';
import CryptoJS from 'crypto-js';

export default class RionsKey extends rionsKeyEncLib {
  private KeySet: NumpadKeymaps;
  private tkUrl: URL;
  private tkEnv: tkParams;
  private tkKeyboardType: 'number';
  private sessionId: string;
  private iv: number[];
  private keyIndex: string;
  private uuid: string;
  private allocationIndex: number;
  private isDebugMode: boolean;
  private pubKey: string;

  constructor(keySet: NumpadKeymaps, transkeyServlet: URL, iv: number[], isDebugMode?: boolean) {
    super();
    this.KeySet = keySet;
    this.tkUrl = transkeyServlet;
    this.iv = iv
      ? iv
      : [
          0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x4b, 0x65, 0x79, 0x31,
          0x30,
        ];
    this.tkEnv = {
      initTime: '',
      limitTime: 0,
      useSession: false,
      useSpace: false,
      useGenKey: false,
      useTalkBack: false,
      java_ver: 1.8,
    };
    isDebugMode ? (this.isDebugMode = true) : (this.isDebugMode = false);
    this.uuid = crypto.randomBytes(32).toString('hex');
    this.allocationIndex = parseInt(crypto.randomBytes(32).toString('hex').substring(0, 8), 16);
    this.sessionId = crypto.randomBytes(32).toString('hex').substring(0, 16);
  }
  async createSession(keyboardType: 'number') {
    this.tkKeyboardType = keyboardType;
    return this.getTkParams().then(async () => {
      await this.getPublicKey();
      await this.getKeyIndex(this.tkKeyboardType);
    });
  }

  async getTkParams() {
    return await got
      .get(this.tkUrl, {
        searchParams: {
          op: 'getInitTime',
        },
      })
      .then((res) => {
        let parsed = parse(res.body).program.body;
        this.isDebugMode ? console.log('getTkParams >> Received Data. Mapping started.') : null;
        parsed.forEach((untypedObj) => {
          let VariableObj = untypedObj as VariableDeclaration;
          let idObj = VariableObj.declarations[0].id as Identifier;
          let initObj = VariableObj.declarations[0].init as
            | NumericLiteral
            | BooleanLiteral
            | StringLiteral;

          this.isDebugMode
            ? console.log(`${idObj.name}: ${initObj.value} (${typeof initObj.value})`)
            : null;

          switch (idObj.name) {
            case 'initTime':
              typeof initObj.value === 'string' ? (this.tkEnv.initTime = initObj.value) : null;
              break;
            case 'limitTime':
              typeof initObj.value === 'number' ? (this.tkEnv.limitTime = initObj.value) : null;
              break;
            case 'useSession':
              typeof initObj.value === 'boolean' ? (this.tkEnv.useSession = initObj.value) : null;
              break;
            case 'useSpace':
              typeof initObj.value === 'boolean' ? (this.tkEnv.useSpace = initObj.value) : null;
              break;
            case 'useTalkBack':
              typeof initObj.value === 'boolean' ? (this.tkEnv.useTalkBack = initObj.value) : null;
              break;
            case 'useGenKey':
              typeof initObj.value === 'boolean' ? (this.tkEnv.useGenKey = initObj.value) : null;
              break;
            case 'java_ver':
              typeof initObj.value === 'number' ? (this.tkEnv.java_ver = initObj.value) : null;
              break;
            default:
              throw new Error('Server Sent invaild variable');
          }
        });
        this.isDebugMode ? console.log('getTkParams >> tkEnv mapping complated.') : null;
        return this.tkEnv;
      })
      .catch((err) => {
        throw new Error(err);
      });
  }

  async getPublicKey() {
    return await got
      .get(this.tkUrl, {
        searchParams: {
          op: 'getPublicKey',
        },
      })
      .then((res) => {
        this.pubKey = res.body;
        this.isDebugMode
          ? console.log(
              `getPublicKey >> OK, is ${
                res.body.length === 1152
                  ? 'Vaild data (1152)'
                  : `INVAILD DATA! (${res.body.length})`
              }`,
            )
          : null;
        return this.pubKey;
      })
      .catch((err) => {
        throw new Error(err);
      });
  }

  async getKeyIndex(keyboardType: 'number', reqParams?: requestParams) {
    return await got
      .post(this.tkUrl, {
        searchParams: {
          op: 'getKeyIndex',
          name: 'password',
          keyType: 'single',
          keyboardType: keyboardType,
          fieldType: 'password',
          inputName: 'password',
          parentKeyboard: false,
          transkeyUuid: this.uuid,
          exE2E: reqParams?.exE2E ? reqParams?.exE2E : false,
          TK_requestToken: reqParams?.TK_requestToken ? reqParams?.TK_requestToken : 0,
          isCrt: reqParams?.isCrt ? reqParams?.isCrt : false,
          allocationIndex: this.allocationIndex,
          keyIndex: '',
          initTime: this.tkEnv.initTime,
          talkBack: true,
        },
      })
      .then((res) => {
        this.checkReqEnv(res.requestUrl);
        this.keyIndex = res.body;
        this.isDebugMode
          ? console.log(
              `getKeyIndex >> OK, is ${
                res.body.length === 512 ? 'Vaild data (512).' : `INVAILD DATA! (${res.body.length})`
              }`,
            )
          : null;
        return this.keyIndex;
      })
      .catch((err) => {
        throw new Error(err);
      });
  }

  async mapButtonData(reqParams?: requestParams) {
    return await got
      .post(this.tkUrl, {
        searchParams: {
          op: 'getDummy',
          name: this.tkKeyboardType,
          keyType: 'single',
          keyboardType: this.tkKeyboardType,
          fieldType: 'password',
          inputName: 'password',
          parentKeyboard: false,
          transkeyUuid: this.uuid,
          exE2E: reqParams?.exE2E ? reqParams?.exE2E : false,
          TK_requestToken: reqParams?.TK_requestToken ? reqParams?.TK_requestToken : 0,
          isCrt: reqParams?.isCrt ? reqParams?.isCrt : false,
          allocationIndex: this.allocationIndex,
          keyIndex: this.keyIndex,
          initTime: this.tkEnv.initTime,
          talkBack: true,
        },
      })
      .then((res) => {
        this.checkReqEnv();
        let parsed = res.body.replace(new RegExp(/([,])/g), '');
        let result: Button[] = [];

        for (let i = 0; i < parsed.length; i++) {
          let now = parsed.charAt(i);
          if (now === '=') {
          } else if (now === 'e' || now === 'c' || now === 'b') {
            // Mapping Buttons: keyboard
          } else {
            // Mapping Buttons: Numpad
            let nowButton: Button;
            switch (i) {
              case 0:
                nowButton = this.KeySet.numpad_0;
                break;
              case 1:
                nowButton = this.KeySet.numpad_1;
                break;
              case 2:
                nowButton = this.KeySet.numpad_2;
                break;
              case 3:
                nowButton = this.KeySet.numpad_3;
                break;
              case 4:
                nowButton = this.KeySet.numpad_4;
                break;
              case 5:
                nowButton = this.KeySet.numpad_5;
                break;
              case 6:
                nowButton = this.KeySet.numpad_6;
                break;
              case 7:
                nowButton = this.KeySet.numpad_7;
                break;
              case 8:
                nowButton = this.KeySet.numpad_8;
                break;
              case 9:
                nowButton = this.KeySet.numpad_9;
                break;
              case 10:
                nowButton = this.KeySet.numpad_10;
                break;
              case 11:
                nowButton = this.KeySet.numpad_11;
                break;
              default:
                throw new Error('mapButtonData >> invaild button index!');
            }
            result.push(nowButton);
          }
        }
        return result;
      })
      .catch((err) => {
        throw new Error(err);
      });
  }

  getTkInputable(buttonData?: Button, length?: number) {
    length = length ? length : 48; // Default length: 48
    let result = new Array<number>(length);
    let uppercase = /^[\x61-\x7A]*$/; // uppercase RegExp
    let inputable = buttonData ? `${buttonData.x} ${buttonData.y}` : '# 0 0'; // # 0 0 : Finish String
    let i;

    for (i = 0; i < length; i++) {
      if (i < inputable.length) {
        let nowChar = inputable.charAt(i);
        if (nowChar == 'l' || nowChar == 'u' || nowChar == '#') {
          // Special Character: l, u, # => Converting Number
          result[i] = Number(inputable.charCodeAt(i));
        } else if (inputable.charAt(i) == ' ') {
          // Empty Character: ' ' => 0
          result[i] = Number(inputable.charCodeAt(i));
        } else {
          // Normal Character: Coverted String => Converting Number
          result[i] = Number(inputable.charAt(i).toString());
        }
      } else if (!this.tkEnv.useSession && this.tkEnv.limitTime > 0) {
        // if using session, then don't need to include limitTime.
        // if not using session, then need to include limitTime.
        i = inputable.length - 1;
        result[i++] = 32;
        for (let j = 0; j < this.tkEnv.initTime.length; j++) {
          // if some initTime character is uppercase, then include character index.
          result[i++] = uppercase.test(this.tkEnv.initTime[j])
            ? Number(this.tkEnv.initTime.charCodeAt(j))
            : Number(this.tkEnv.initTime[j]);
        }
        break;
      }
    }

    result[i++] = 32;
    result[i++] = 37;

    while (i < length) {
      // Filling Empty Space from Random Bytes.
      result[i] = parseInt(crypto.randomBytes(32).toString('hex').substring(0, 8), 16) % 100;
      i++;
    }
    return result;
  }

  encrypt(SeletedButtons: Button[]) {
    let maxLength =
      SeletedButtons.length +
      (parseInt(crypto.randomBytes(32).toString('hex').substring(0, 8), 16) % 10);
    let encryptedString: string = '';

    // First, encrypt the buttons.
    for (let button of SeletedButtons) {
      // Encrypt Button
      let TkInputable = this.getTkInputable(button);
      let roundKey = this.makeRoundKey(TkInputable);
      let encrypted = this.cbcEncrypt(TkInputable, this.iv, roundKey, 48);

      // push encrypted data (hex string)
      encryptedString = encryptedString.concat(this.getHexString(encrypted));
    }

    // Second, fillin the empty space. (repeat encrypt string '# 0 0')
    for (let i = 0; i < maxLength; i++) {
      // Finishing Encrypt: '# 0 0'
      let TkInputable = this.getTkInputable();
      let roundKey = this.makeRoundKey(TkInputable);
      let encrypted = this.cbcEncrypt(TkInputable, this.iv, roundKey, 48);

      // push encrypted data (hex string)
      encryptedString = encryptedString.concat(this.getHexString(encrypted));
    }

    return encryptedString;
  }

  sendData(encryptedString: number[]) {
    let encString = this.getHexString([...encryptedString]);
    let hmac: string;

    this.tkEnv.java_ver < 1.5
      ? (hmac = CryptoJS.HmacSHA1(encString, this.sessionId).toString(CryptoJS.enc.Utf8))
      : (hmac = CryptoJS.HmacSHA256(encString, this.sessionId).toString(CryptoJS.enc.Utf8));
  }

  getHexString(data: number[]) {
    let dataString = Buffer.from(data).toString('hex');
    let dataArray: string[] = [];
    for (let i = 0; i < dataString.length; i++) {
      let now = dataString.substring(i++, i + 1);
      now.startsWith('0') ? dataArray.push(now.charAt(1)) : dataArray.push(now);
    }
    return `$${dataArray.join(',')}`;
  }

  private checkReqEnv(originalUrl?: string) {
    // debug function for check environment variables.
    // it shows tkEnv and requested url.
    if (!this.isDebugMode) return null;
    console.dir('checkReqEnv >> Started.');
    console.dir(this.tkEnv);
    if (originalUrl) {
      console.log(`res.requestUrl: ${originalUrl}`);
    }

    return true;
  }
}
