//Add custom adaptor to send anti-forgery token while performing CRUD operation from Grid Control.
window.customAdaptor = new ej.data.UrlAdaptor();
customAdaptor = ej.base.extend(customAdaptor, {
    processResponse: function (data, ds, query, xhr, request, changes) {
        // request.data = JSON.stringify(data);
        // return ej.data.UrlAdaptor.prototype.processResponse.call(this, data, ds, query, xhr, request, changes)

        if (!ej.base.isNullOrUndefined(data.message)) {

            if (data.success) {
                toastr.success(data.message);
            }
            else {
                toastr.error(data.message);
            }
            // alert(data.message);
        }
        if (!ej.base.isNullOrUndefined(data.data))
            return data.data;
        else
            return data;
    },

    insert: function (dm, data, tableName) {
        return {
            url: dm.dataSource.insertUrl,
            // data: $.param({
            data: JSON.stringify({
                // __RequestVerificationToken: document.getElementsByName("__RequestVerificationToken")[0].value,
                __RequestVerificationToken: "Syncfusion",
                value: data,
                table: tableName,
                action: 'insert'
            }),
            // contentType: 'application/x-www-form-urlencoded; charset=UTF-8'
        }
    },

    update: function (dm, keyField, value, tableName) {
        return {
            url: dm.dataSource.updateUrl,
            // data: $.param({
            data: JSON.stringify({
                // __RequestVerificationToken: document.getElementsByName("__RequestVerificationToken")[0].value,
                __RequestVerificationToken: "Syncfusion",
                value: value,
                table: tableName,
                //action: 'insert'
                action: 'update'
            }),
            // contentType: 'application/x-www-form-urlencoded; charset=UTF-8'
        };
    },

});



function resetWindowFetch() {
    if (!nnotytoastFetch) {
        nnotytoastFetch = window.fetch; // Save the nnotytoast's fetch
    }
    window.fetch = originalFetch;
}

function restoreNnotytoastFetch() {
    if (nnotytoastFetch) {
        window.fetch = nnotytoastFetch; // Restore the nnotytoast's fetch
    }
}


function postToController(url, data) {
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            // 'RequestVerificationToken': document.querySelector('input[name="__RequestVerificationToken"]').value
        },
        body: JSON.stringify(data)
    })
        .then(response => {
            if (!response.ok) {
                toastr.error(error);
                //throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                toastr.success(data.message);
            }
            else {
                toastr.error(data.message);
            }
            // console.log('Success:', data);
            RefreshGrid();
        })
        .catch(error => {
            toastr.error(error);
            //console.error('Error:', error);
        });
}


function alphaNumericValidation(args) {
    return (args['value'].match(/^[A-Za-z0-9 àáâäæçèéêëìíîïòóôœùúûüÿÀÁÂÄÆÇÈÉÊËÌÍÎÏÒÓÔŒÙÚÛÜŸ]+$/)); // Allow alphanumeric and French characters
}
function domainValidation(args) {
    return (args['value'].match(/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/)); // validate domain format
}
function emailValidation(args) {
    return (args['value'].match(/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/)); // validate email format
}
//function isValidUrl(url) {
//    //const urlPattern = /^(https?:\/\/)?(localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[\w-]+([.][\w-]+)+)(:\d+)?(\/[^\s]*)?$/i;
//    //return urlPattern.test(url);
//    //const pattern = /^(https?:\/\/)?([\w-]+(\.[\w-]+)*|localhost)(:\d+)?(\/.*)?$/;
//    //return pattern.test(url);
//    //try {
//    //    //new URL(url);
//    //    //return true;
//    //    let parsedUrl = new URL(url);
//    //    return parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:";
//    //} catch {
//    //    return false;
//    //}

//    try {
//        // First check if it's a localhost URL
//        if (url.includes('localhost')) {
//            return /^(https?:\/\/)?localhost(:\d+)?(\/[\w\-._~:/?#[\]@!$&'()*+,;=]*)?$/i.test(url);
//        }

//        // For all other URLs, use a more permissive pattern
//        return /^(https?:\/\/)?([\w\-]+\.)+[\w\-]+(:\d+)?(\/[\w\-._~:/?#[\]@!$&'()*+,;=]*)?$/i.test(url);
//    } catch {
//        return false;
//    }
//}
