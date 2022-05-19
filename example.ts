import RionsKey from './src/RionsKey';
import { numpad } from './keymap.json';

let tk = new RionsKey(numpad, new URL('https://hcs.eduro.go.kr/transkeyServlet'));

(async () => {
  await tk.createSession('number');
  let numbers = await tk.mapButtonData();
  let EncResult = tk.encrypt([numbers[0], numbers[4], numbers[1], numbers[0]]);
  console.log(tk.getFormattedData(EncResult));
})();
