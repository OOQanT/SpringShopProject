package image.upload.uploadtest.controller.order;

import image.upload.uploadtest.dto.order.*;
import image.upload.uploadtest.jwt.JWTUtil;
import image.upload.uploadtest.service.order.OrderService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.NoSuchElementException;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/order")
public class OrderController {

    private final OrderService orderService;
    private final JWTUtil jwtUtil;

    @PostMapping("/create_Order")
    public ResponseEntity<CreateOrderResponse> create_Order(HttpServletRequest request, @RequestBody CreateOrderRequest createOrderRequest){
        String requestUsername = getUsername(request);

        try{
            Long orderId = orderService.addOrder(requestUsername,createOrderRequest);

            return ResponseEntity.status(HttpServletResponse.SC_CREATED)
                    .body(new CreateOrderResponse(orderId,"성공"));

        }catch (NoSuchElementException | IllegalArgumentException e){
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new CreateOrderResponse(e.getMessage()));
        }
    }

    @PutMapping("/{orderId}/cancel")
    public ResponseEntity<CancelOrderResponse> cancel(@PathVariable Long orderId){
        try{
            Long order = orderService.cancelOrder(orderId);
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body(new CancelOrderResponse(order,"주문 취소"));
        }catch (NoSuchElementException e){
            return ResponseEntity.status(HttpServletResponse.SC_NOT_FOUND)
                    .body(new CancelOrderResponse(e.getMessage()));
        }
    }

    @GetMapping("/order_list")
    public ResponseEntity<GetOrderListResponse> order_list(HttpServletRequest request){

        String requestUsername = getUsername(request);
        try{
            List<GetOrderDto> orders = orderService.getOrders(requestUsername);

            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body(new GetOrderListResponse(orders.size(), orders,"성공"));

        }catch (NoSuchElementException e){
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new GetOrderListResponse(e.getMessage()));
        }
    }

    private String getUsername(HttpServletRequest request){
        String token = request.getHeader("Authorization").split(" ")[1];
        return jwtUtil.getUsername(token);
    }
}
