// Please see documentation at https://docs.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

//Check values of textboxes and disable the 'Convert' button accordingly:
$(".watchme").keyup(function () {
    CheckTextBoxesOnSubmit();
});
function CheckTextBoxesOnSubmit() {
    //debugger;
    if (($("#plainText").val() !== "" && $("#cipherText").val() !== "") ||
        ($("#plainText").val() === "" && $("#cipherText").val() === "")) {
        $("#convertButton").prop('disabled', true);
    }
    else {
        $("#convertButton").prop('disabled', false);
    }
}
function Reset() {
    $("#plainText").val("");
    $("#cipherText").val("");
}
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
async function demo() {
    console.log("Available Routes:");
    console.log(window.location.origin + "/api/Security/encrypt");
    console.log(window.location.origin + "/api/Security/decrypt");
    console.log("Both routes expecting the following JSON object:");
    console.log('{"plainText":"banana","cipherText":""}');
}

$(document).ready(function () {
    CheckTextBoxesOnSubmit();
    demo();
});
