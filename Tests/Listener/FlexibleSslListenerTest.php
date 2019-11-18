<?php

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\Tests\Listener;

use Nelmio\SecurityBundle\EventListener\FlexibleSslListener;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpFoundation\RedirectResponse;

class FlexibleSslListenerTest extends \PHPUnit\Framework\TestCase
{
    private $kernel;
    private $dispatcher;
    private $listener;

    protected function php5and7setUp()
    {
        $this->kernel = $this->getMockBuilder('Symfony\Component\HttpKernel\HttpKernelInterface')->getMock();
        $this->dispatcher = $this->getMockBuilder('Symfony\Component\EventDispatcher\EventDispatcherInterface')->getMock();
        $this->listener = new FlexibleSslListener('auth', false, $this->dispatcher);
    }

    public function testKernelRequestWithNonAuthedNonSslRequest()
    {
        $this->php5and7setUp();

        $request = Request::create('http://localhost/');

        $event = new GetResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testKernelRequestWithAuthedNonSslRequest()
    {
        $this->php5and7setUp();

        $request = Request::create('http://localhost/');
        $request->cookies->set('auth', '1');

        $event = new GetResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $this->listener->onKernelRequest($event);

        $this->assertTrue($event->hasResponse());
        $this->assertTrue($event->getResponse()->isRedirection());
    }

    public function testKernelRequestWithNonAuthedSslRequest()
    {
        $this->php5and7setUp();

        $request = Request::create('https://localhost/');

        $event = new GetResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testKernelRequestWithAuthedSslRequest()
    {
        $this->php5and7setUp();

        $request = Request::create('https://localhost/');
        $request->cookies->set('auth', '1');

        $event = new GetResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testPostLoginKernelResponse()
    {
        $this->php5and7setUp();

        $request = Request::create('https://localhost/');

        $response = new Response();

        $event = new FilterResponseEvent($this->kernel, $request, HttpKernelInterface::MASTER_REQUEST, $response);
        $this->listener->onPostLoginKernelResponse($event);

        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        $this->assertTrue(isset($cookies['']['/']['auth']));
        $this->assertSame('1', $cookies['']['/']['auth']->getValue());
        $this->assertFalse($cookies['']['/']['auth']->isSecure());

        $this->assertTrue(isset($cookies['']['/'][session_name()]));
        $this->assertSame(session_id(), $cookies['']['/'][session_name()]->getValue());
        $this->assertTrue($cookies['']['/'][session_name()]->isSecure());
    }

    public function testKernelRequestSkipsSubReqs()
    {
        $this->php5and7setUp();

        $request = Request::create('http://localhost/');
        $request->cookies->set('auth', '1');

        $event = new GetResponseEvent($this->kernel, $request, HttpKernelInterface::SUB_REQUEST);
        $this->listener->onKernelRequest($event);

        $this->assertFalse($event->hasResponse());
    }

    public function testPostLoginKernelResponseSkipsSubReqs()
    {
        $this->php5and7setUp();

        $request = Request::create('https://localhost/');

        $response = new Response();

        $event = new FilterResponseEvent($this->kernel, $request, HttpKernelInterface::SUB_REQUEST, $response);
        $this->listener->onPostLoginKernelResponse($event);

        $cookies = $response->headers->getCookies(ResponseHeaderBag::COOKIES_ARRAY);
        $this->assertFalse(isset($cookies['']['/']['auth']));
    }

    public function testSecureLogout()
    {
        $this->php5and7setUp();

        $response = new RedirectResponse('https://foo');
        $request = $this->getMockBuilder('Symfony\Component\HttpFoundation\Request')->getMock();
        $token = $this->getMockBuilder('Symfony\Component\Security\Core\Authentication\Token\TokenInterface')->getMock();

        $this->listener->logout($request, $response, $token);

        $this->assertSame('https://foo', $response->headers->get('Location'));
    }

    public function testUnsecuredLogout()
    {
        $this->php5and7setUp();

        $unsecuredLogoutListener = new FlexibleSslListener('auth', true, $this->dispatcher);

        $response = new RedirectResponse('https://foo');
        $request = $this->getMockBuilder('Symfony\Component\HttpFoundation\Request')->getMock();
        $token = $this->getMockBuilder('Symfony\Component\Security\Core\Authentication\Token\TokenInterface')->getMock();

        $unsecuredLogoutListener->logout($request, $response, $token);

        $this->assertSame('http://foo', $response->headers->get('Location'));
    }
}
