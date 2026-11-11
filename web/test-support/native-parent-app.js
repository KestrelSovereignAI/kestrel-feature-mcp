import { App } from '@modelcontextprotocol/ext-apps';

const app = new App({ name: 'Native owned acceptance App', version: '1.0.0' }, {});
const result = document.createElement('pre'); result.id = 'native-result'; document.body.append(result);
app.ontoolresult = value => { result.textContent = JSON.stringify(value._meta?.['private-result']); };
function button(label, name, arguments_) {
    const element = document.createElement('button'); element.textContent = label;
    element.onclick = async () => {
        try {
            const value = await app.callServerTool({ name, arguments: arguments_ });
            result.textContent = value.isError ? 'native-call-refused'
                : 'native-call:' + JSON.stringify(value._meta?.['private-result']);
        } catch (error) {
            result.textContent = name === 'echo' ? 'model-only-refused' : 'native-call-failed:' + error.message;
        }
    };
    document.body.append(element);
}
button('Native governed call', 'app_mutate', { text: 'browser-app-once' });
button('Try model-only tool', 'echo', { text: 'must-not-forward' });
const catalog = document.createElement('button'); catalog.textContent = 'List App tools';
catalog.onclick = async () => {
    try {
        const value = await app.request({ method: 'tools/list', params: {} });
        const names = value.tools.map(tool => tool.name);
        result.textContent = names.includes('app_mutate') && !names.includes('echo')
            ? 'catalog-filtered' : 'catalog-exposed-model-only-tool';
    } catch (error) { result.textContent = 'catalog-failed:' + error.message; }
};
document.body.append(catalog);
await app.connect();
