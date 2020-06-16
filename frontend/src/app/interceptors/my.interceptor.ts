import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpHandler, HttpRequest, HttpEvent, HttpResponse }
  from '@angular/common/http';

import { Observable } from 'rxjs/Observable';
import 'rxjs/add/operator/do';

@Injectable()
export class MyInterceptor implements HttpInterceptor {
  intercept(
    req: HttpRequest<any>,
    next: HttpHandler
  ): Observable<HttpEvent<any>> {

    req =  req.clone({ headers: req.headers });
    console.log(req);
    return next.handle(req).do(evt => {
            if (evt instanceof HttpResponse) {
              console.log('---> HttpResponse:', evt);

        console.log('---> status:', evt.status);
        console.log('---> body:', evt.body);
        console.log('---> headers:', evt.headers);
      }
    });
  }
}
