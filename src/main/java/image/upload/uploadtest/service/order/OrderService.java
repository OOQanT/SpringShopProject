package image.upload.uploadtest.service.order;

import image.upload.uploadtest.dto.order.CreateOrderRequest;
import image.upload.uploadtest.dto.order.GetOrderDto;
import image.upload.uploadtest.entity.*;
import image.upload.uploadtest.repository.cart.CartRepository;
import image.upload.uploadtest.repository.member.MemberRepository;
import image.upload.uploadtest.repository.order.OrderRepository;
import image.upload.uploadtest.repository.orderItem.OrderItemRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class OrderService {

    private final OrderRepository orderRepository;
    private final MemberRepository memberRepository;
    private final CartRepository cartRepository;
    private final OrderItemRepository orderItemRepository;

    public Long addOrder(String requestUsername, CreateOrderRequest createOrderRequest){
        Member findMember = memberRepository.findByUsername(requestUsername)
                .orElseThrow(() -> new NoSuchElementException("등록되지 않은 사용자"));

        List<Cart> findCart = cartRepository.findByMember(findMember);
        if(findCart.isEmpty()){
            throw new IllegalArgumentException("선택된 상품이 없습니다.");
        }

        List<OrderItem> orderItem = OrderItem.createOrderItem(findCart);

        Address address = new Address(createOrderRequest.getAddress(), createOrderRequest.getDetailAddress());

        Order order = Order.createOrder(findMember, orderItem);
        order.setAddress(address);
        if(createOrderRequest.getPayment().equals("카드")){
            order.setPayment(Payment.CARD);
        }else{
            order.setPayment(Payment.BANK);
        }

        orderRepository.save(order);

        return order.getId();
    }

    public Long cancelOrder(Long orderId){
        Order findOrder = orderRepository.findById(orderId)
                .orElseThrow(() -> new NoSuchElementException("주문 정보가 존재하지 않습니다."));

        findOrder.cancel();
        findOrder.setStatus(OrderState.CANCEL);
        return findOrder.getId();
    }

    public List<GetOrderDto> getOrders(String requestUsername){
        Member findMember = memberRepository.findByUsername(requestUsername)
                .orElseThrow(() -> new NoSuchElementException("찾을 수 없는 사용자의 요청"));

        List<Order> findOrders = orderRepository.findByMember(findMember);
        if(findOrders.isEmpty()){
            throw new NoSuchElementException("주문정보가 존재하지 않습니다.");
        }

        List<GetOrderDto> getOrderDtoList = new ArrayList<>();
        for (Order findOrder : findOrders) {
            GetOrderDto getOrderDto = new GetOrderDto();
            getOrderDto.setOrderId(findOrder.getId());
            getOrderDto.setDelivery(findOrder.getDelivery());
            getOrderDto.setOrderTime(findOrder.getOrderTime());
            getOrderDto.setPayment(String.valueOf(findOrder.getPayment()));
            getOrderDto.setOrderState(String.valueOf(findOrder.getStatus()));

            List<OrderItem> findOrderItem = orderItemRepository.findByOrder(findOrder);
            int totalPrice = 0;
            for (OrderItem orderItem : findOrderItem) {
                totalPrice += orderItem.getTotalPrice();
            }
            getOrderDto.setTotalPrice(totalPrice);
            getOrderDtoList.add(getOrderDto);
        }

        return getOrderDtoList;
    }
}
