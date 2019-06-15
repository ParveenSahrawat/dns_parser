function abc() {
    for(let i=1; i<10; i++) {
        if(i%2 === 0) {
            return console.log('Hello');
        } else {
            return console.log("Bye");
            // break;
        }
    }
}

abc(abc(abc()));

[1,2,3,4,5].map((item, index) => {
    if(item%2 === 0)
        return console.log(item +' '+index)
})