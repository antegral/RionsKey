import RionsKey from './src/RionsKey';
import { numpad } from './keymap.json';

let tk = new RionsKey(
  numpad,
  new URL('https://hcs.eduro.go.kr/transkeyServlet'),
  [0x4d, 0x6f, 0x62, 0x69, 0x6c, 0x65, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x4b, 0x65, 0x79, 0x31, 0x30],
);

(async () => {
  await tk.createSession('number');
  let numbers = await tk.mapButtonData();
  let result = tk.encrypt([numbers[0], numbers[4], numbers[1], numbers[0]]);
  console.dir(result);
})();
