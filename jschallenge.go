package bripguard

import (
	"strings"
)

func (g *BripGuard) GetChallenge(sessionId string) (string, error) {
	delayVal, err := g.cfg.Store.GetAndDelete(asKey(sessionId))
	if err != nil {
		return "", err
	}

	urls, finalUrl, err := g.getUrlsBySession(sessionId)
	if err != nil {
		return "", err
	}
	val := `
		(async()=>{await new Promise(resolve=>setTimeout(resolve,@delay));
    	console.log(await[@urls].reduce(async(p,v)=>{const acc=await p;
        if(v[0]==="+"){const finalUrl=v.slice(1)+encodeURIComponent(acc.join("|"));
            return fetch(finalUrl,{
			headers: {
			}
		}).then(res=>res.text());}
			const df=await fetch(v,{
			headers: {
			}
  		}).then(res=>res.text());return [...acc,df];},Promise.resolve([])));})();
	`
	cmburls := ""
	for _, s := range urls {
		cmburls += "\"" + s + "\","
	}
	cmburls += "\"+" + finalUrl + "\""

	return strings.ReplaceAll(strings.ReplaceAll(val, "@urls", cmburls), "@delay", delayVal), nil
}
