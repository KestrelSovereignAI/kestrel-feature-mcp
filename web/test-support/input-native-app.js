import { App } from '@modelcontextprotocol/ext-apps';

const app = new App({ name: 'Owned operator input App', version: '1' }, {});
const result = document.createElement('pre'); result.id = 'input-app-result'; document.body.append(result);
app.ontoolresult = value => { result.textContent = 'native-result:' + value._meta?.['private-witness']; };
const button = document.createElement('button'); button.textContent = 'Request operator input';
button.onclick = async () => {
    try {
        await app.callServerTool({ name: 'mutate_marker', arguments: { marker: 'app-effect' } });
        result.textContent = 'unexpected-complete-result';
    } catch {
        result.textContent = 'waiting-for-host-input';
    }
};
document.body.append(button);
await app.connect();
