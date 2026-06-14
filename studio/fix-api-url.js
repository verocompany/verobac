// fix-api-url.js
import { readFileSync, writeFileSync, readdirSync } from 'fs';
import { join } from 'path';

const OLD_API = 'http://localhost:3001/api';
const NEW_API = 'https://verobac-production.up.railway.app/api';

const htmlFiles = readdirSync('.').filter(f => f.endsWith('.html'));

console.log(`🔧 جاري تعديل ${htmlFiles.length} ملف...`);

htmlFiles.forEach(file => {
    let content = readFileSync(file, 'utf8');
    if (content.includes(OLD_API)) {
        const newContent = content.replaceAll(OLD_API, NEW_API);
        writeFileSync(file, newContent, 'utf8');
        console.log(`✅ تم تعديل: ${file}`);
    } else if (content.includes('verobac-production.up.railway.app')) {
        console.log(`⏭️  بالفعل محدث: ${file}`);
    } else {
        console.log(`⚠️  لم يتم العثور على API_URL في: ${file}`);
    }
});

console.log('🎉 تم الانتهاء من التعديل!');