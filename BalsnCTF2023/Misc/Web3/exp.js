// const { messagePrefix } = require("@ethersproject/hash");
// const ethers = require("ethers");


// const  generateRandomString = (num) => {
//     let result1= Math.random().toString(36).substring(2,) + Math.random().toString(36).substring(2,) + Math.random().toString(36).substring(2,) + Math.random().toString(36).substring(2,);       
//     console.log(result1.substring(0, num));
//     return result1.substring(0, num);
// }


// async function signAndVerify() {
//     let privateKey = "0x3141592653589793238462643383279502884197169399375105820974944592";
//     let wallet = new ethers.Wallet(privateKey);
    
//     try{
//         while(true){
//             message = generateRandomString(40);
//             const signature = await wallet.signMessage(message);
//             console.log(signature);
//             console.log(ethers.utils.verifyMessage(message, signature));
//             console.log('0x' + message);
//             if (ethers.utils.verifyMessage(message, signature) === '0x' + message){
//                 console.log("Got it\nThe mssage is: ", message);
//                 break;
//             }

//             console.log("Nothing Yet");
//         }
//     } catch (error){
//         console.log("Errror");
//     }
// }

// signAndVerify();

const ethers = require("ethers")

const wallet = ethers.Wallet.createRandom()
console.log(ethers.utils.getAddress(wallet.address))
const icapAddress = ethers.utils.getIcapAddress(wallet.address)
console.log(icapAddress)

const message = icapAddress
const signature = wallet.signMessage(message)
console.log(message, signature)